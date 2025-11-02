package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"github.com/korotovsky/slack-mcp-server/pkg/server/auth"
	"github.com/korotovsky/slack-mcp-server/pkg/text"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/slack-go/slack"
	slackGoUtil "github.com/takara2314/slack-go-util"
	"go.uber.org/zap"
)

const (
	defaultConversationsNumericLimit    = 50
	defaultConversationsExpressionLimit = "1d"
)

var validFilterKeys = map[string]struct{}{
	"is":     {},
	"in":     {},
	"from":   {},
	"with":   {},
	"before": {},
	"after":  {},
	"on":     {},
	"during": {},
}

// sanitizeRemoveInFilters removes any existing in:<token> filters from a Slack search query
func sanitizeRemoveInFilters(q string) string {
	re := regexp.MustCompile(`\bin:[^\s]+`)
	s := re.ReplaceAllString(q, "")
	// Normalize whitespace
	return strings.Join(strings.Fields(s), " ")
}

type Message struct {
	MsgID     string `json:"msgID"`
	UserID    string `json:"userID"`
	UserName  string `json:"userUser"`
	RealName  string `json:"realName"`
	Channel   string `json:"channelID"`
	ThreadTs  string `json:"ThreadTs"`
	Text      string `json:"text"`
	Time      string `json:"time"`
	Reactions string `json:"reactions,omitempty"`
	Cursor    string `json:"cursor"`
}

type User struct {
	UserID   string `json:"userID"`
	UserName string `json:"userName"`
	RealName string `json:"realName"`
}

type conversationParams struct {
	channel  string
	limit    int
	oldest   string
	latest   string
	cursor   string
	activity bool
}

type searchParams struct {
	query             string
	limit             int
	page              int
	channels          []string // Multiple channels
	minThreadReplies  int      // Minimum thread replies
	dayOfWeek         string   // Specific day of week (monday, tuesday, etc.)
	hourRangeStart    int      // Start hour in UTC (0-23)
	hourRangeEnd      int      // End hour in UTC (0-23)
	postSearchFilters bool     // Whether post-search filtering is needed
}

type addMessageParams struct {
	channel     string
	threadTs    string
	text        string
	contentType string
}

type ConversationsHandler struct {
	apiProvider *provider.ApiProvider
	logger      *zap.Logger
}

func NewConversationsHandler(apiProvider *provider.ApiProvider, logger *zap.Logger) *ConversationsHandler {
	return &ConversationsHandler{
		apiProvider: apiProvider,
		logger:      logger,
	}
}

// UsersResource streams a CSV of all users
func (ch *ConversationsHandler) UsersResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	ch.logger.Debug("UsersResource called", zap.Any("params", request.Params))

	// authentication
	if authenticated, err := auth.IsAuthenticated(ctx, ch.apiProvider.ServerTransport(), ch.logger); !authenticated {
		ch.logger.Error("Authentication failed for users resource", zap.Error(err))
		return nil, err
	}

	// provider readiness
	if ready, err := ch.apiProvider.IsReady(); !ready {
		ch.logger.Error("API provider not ready", zap.Error(err))
		return nil, err
	}

	// Slack auth test
	ar, err := ch.apiProvider.Slack().AuthTest()
	if err != nil {
		ch.logger.Error("Slack AuthTest failed", zap.Error(err))
		return nil, err
	}

	ws, err := text.Workspace(ar.URL)
	if err != nil {
		ch.logger.Error("Failed to parse workspace from URL",
			zap.String("url", ar.URL),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to parse workspace from URL: %v", err)
	}

	// collect users
	usersMaps := ch.apiProvider.ProvideUsersMap()
	users := usersMaps.Users
	usersList := make([]User, 0, len(users))
	for _, user := range users {
		usersList = append(usersList, User{
			UserID:   user.ID,
			UserName: user.Name,
			RealName: user.RealName,
		})
	}

	// marshal CSV
	csvBytes, err := gocsv.MarshalBytes(&usersList)
	if err != nil {
		ch.logger.Error("Failed to marshal users to CSV", zap.Error(err))
		return nil, err
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "slack://" + ws + "/users",
			MIMEType: "text/csv",
			Text:     string(csvBytes),
		},
	}, nil
}

// ConversationsAddMessageHandler posts a message and returns it as CSV
func (ch *ConversationsHandler) ConversationsAddMessageHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsAddMessageHandler called", zap.Any("params", request.Params))

	params, err := ch.parseParamsToolAddMessage(request)
	if err != nil {
		ch.logger.Error("Failed to parse add-message params", zap.Error(err))
		return nil, err
	}

	var options []slack.MsgOption
	if params.threadTs != "" {
		options = append(options, slack.MsgOptionTS(params.threadTs))
	}

	switch params.contentType {
	case "text/plain":
		options = append(options, slack.MsgOptionDisableMarkdown())
		options = append(options, slack.MsgOptionText(params.text, false))
	case "text/markdown":
		blocks, err := slackGoUtil.ConvertMarkdownTextToBlocks(params.text)
		if err != nil {
			ch.logger.Warn("Markdown parsing error", zap.Error(err))
			options = append(options, slack.MsgOptionDisableMarkdown())
			options = append(options, slack.MsgOptionText(params.text, false))
		} else {
			options = append(options, slack.MsgOptionBlocks(blocks...))
		}
	default:
		return nil, errors.New("content_type must be either 'text/plain' or 'text/markdown'")
	}

	unfurlOpt := os.Getenv("SLACK_MCP_ADD_MESSAGE_UNFURLING")
	if text.IsUnfurlingEnabled(params.text, unfurlOpt, ch.logger) {
		options = append(options, slack.MsgOptionEnableLinkUnfurl())
	} else {
		options = append(options, slack.MsgOptionDisableLinkUnfurl())
		options = append(options, slack.MsgOptionDisableMediaUnfurl())
	}

	ch.logger.Debug("Posting Slack message",
		zap.String("channel", params.channel),
		zap.String("thread_ts", params.threadTs),
		zap.String("content_type", params.contentType),
	)
	respChannel, respTimestamp, err := ch.apiProvider.Slack().PostMessageContext(ctx, params.channel, options...)
	if err != nil {
		ch.logger.Error("Slack PostMessageContext failed", zap.Error(err))
		return nil, err
	}

	toolConfig := os.Getenv("SLACK_MCP_ADD_MESSAGE_MARK")
	if toolConfig == "1" || toolConfig == "true" || toolConfig == "yes" {
		err := ch.apiProvider.Slack().MarkConversationContext(ctx, params.channel, respTimestamp)
		if err != nil {
			ch.logger.Error("Slack MarkConversationContext failed", zap.Error(err))
			return nil, err
		}
	}

	// fetch the single message we just posted
	historyParams := slack.GetConversationHistoryParameters{
		ChannelID: respChannel,
		Limit:     1,
		Oldest:    respTimestamp,
		Latest:    respTimestamp,
		Inclusive: true,
	}
	history, err := ch.apiProvider.Slack().GetConversationHistoryContext(ctx, &historyParams)
	if err != nil {
		ch.logger.Error("GetConversationHistoryContext failed", zap.Error(err))
		return nil, err
	}
	ch.logger.Debug("Fetched conversation history", zap.Int("message_count", len(history.Messages)))

	messages := ch.convertMessagesFromHistory(history.Messages, historyParams.ChannelID, false)
	return marshalMessagesToCSV(messages)
}

// ConversationsHistoryHandler streams conversation history as CSV
func (ch *ConversationsHandler) ConversationsHistoryHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsHistoryHandler called", zap.Any("params", request.Params))

	params, err := ch.parseParamsToolConversations(request)
	if err != nil {
		ch.logger.Error("Failed to parse history params", zap.Error(err))
		return nil, err
	}
	ch.logger.Debug("History params parsed",
		zap.String("channel", params.channel),
		zap.Int("limit", params.limit),
		zap.String("oldest", params.oldest),
		zap.String("latest", params.latest),
		zap.Bool("include_activity", params.activity),
	)

	historyParams := slack.GetConversationHistoryParameters{
		ChannelID: params.channel,
		Limit:     params.limit,
		Oldest:    params.oldest,
		Latest:    params.latest,
		Cursor:    params.cursor,
		Inclusive: false,
	}
	history, err := ch.apiProvider.Slack().GetConversationHistoryContext(ctx, &historyParams)
	if err != nil {
		ch.logger.Error("GetConversationHistoryContext failed", zap.Error(err))
		return nil, err
	}

	ch.logger.Debug("Fetched conversation history", zap.Int("message_count", len(history.Messages)))

	messages := ch.convertMessagesFromHistory(history.Messages, params.channel, params.activity)

	if len(messages) > 0 && history.HasMore {
		messages[len(messages)-1].Cursor = history.ResponseMetaData.NextCursor
	}
	return marshalMessagesToCSV(messages)
}

// ConversationsRepliesHandler streams thread replies as CSV
func (ch *ConversationsHandler) ConversationsRepliesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsRepliesHandler called", zap.Any("params", request.Params))

	params, err := ch.parseParamsToolConversations(request)
	if err != nil {
		ch.logger.Error("Failed to parse replies params", zap.Error(err))
		return nil, err
	}
	threadTs := request.GetString("thread_ts", "")
	if threadTs == "" {
		ch.logger.Error("thread_ts not provided for replies", zap.String("thread_ts", threadTs))
		return nil, errors.New("thread_ts must be a string")
	}

	repliesParams := slack.GetConversationRepliesParameters{
		ChannelID: params.channel,
		Timestamp: threadTs,
		Limit:     params.limit,
		Oldest:    params.oldest,
		Latest:    params.latest,
		Cursor:    params.cursor,
		Inclusive: false,
	}
	replies, hasMore, nextCursor, err := ch.apiProvider.Slack().GetConversationRepliesContext(ctx, &repliesParams)
	if err != nil {
		ch.logger.Error("GetConversationRepliesContext failed", zap.Error(err))
		return nil, err
	}
	ch.logger.Debug("Fetched conversation replies", zap.Int("count", len(replies)))

	messages := ch.convertMessagesFromHistory(replies, params.channel, params.activity)
	if len(messages) > 0 && hasMore {
		messages[len(messages)-1].Cursor = nextCursor
	}
	return marshalMessagesToCSV(messages)
}

func (ch *ConversationsHandler) ConversationsSearchHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsSearchHandler called", zap.Any("params", request.Params))

	params, err := ch.parseParamsToolSearch(request)
	if err != nil {
		ch.logger.Error("Failed to parse search params", zap.Error(err))
		return nil, err
	}
	ch.logger.Debug("Search params parsed", zap.String("query", params.query), zap.Int("limit", params.limit), zap.Int("page", params.page))

	var allMessages []slack.SearchMessage

	// Handle multi-channel search
	if len(params.channels) > 0 {
		for _, channelName := range params.channels {
			// Create query with specific channel filter (remove any existing in:... first)
			baseQuery := sanitizeRemoveInFilters(params.query)
			queryWithChannel := strings.TrimSpace(baseQuery + " in:" + channelName)

			searchParams := slack.SearchParameters{
				Sort:          slack.DEFAULT_SEARCH_SORT,
				SortDirection: slack.DEFAULT_SEARCH_SORT_DIR,
				Highlight:     false,
				Count:         params.limit,
				Page:          params.page,
			}

			messagesRes, _, err := ch.apiProvider.Slack().SearchContext(ctx, queryWithChannel, searchParams)
			if err != nil {
				ch.logger.Error("Slack SearchContext failed for channel", zap.String("channel", channelName), zap.Error(err))
				return nil, err
			}
			ch.logger.Debug("Search completed for channel", zap.String("channel", channelName), zap.Int("matches", len(messagesRes.Matches)))

			allMessages = append(allMessages, messagesRes.Matches...)
		}

		// Sort merged messages by timestamp (descending - most recent first)
		sort.Slice(allMessages, func(i, j int) bool {
			return allMessages[i].Timestamp > allMessages[j].Timestamp
		})
	} else {
		// Single search or no specific channel
		searchParams := slack.SearchParameters{
			Sort:          slack.DEFAULT_SEARCH_SORT,
			SortDirection: slack.DEFAULT_SEARCH_SORT_DIR,
			Highlight:     false,
			Count:         params.limit,
			Page:          params.page,
		}

		messagesRes, _, err := ch.apiProvider.Slack().SearchContext(ctx, params.query, searchParams)
		if err != nil {
			ch.logger.Error("Slack SearchContext failed", zap.Error(err))
			return nil, err
		}
		ch.logger.Debug("Search completed", zap.Int("matches", len(messagesRes.Matches)))

		allMessages = messagesRes.Matches
	}

	// Apply post-search filters (day of week, hour range, min thread replies)
	if params.postSearchFilters {
		allMessages, err = ch.applyPostSearchFilters(ctx, allMessages, params)
		if err != nil {
			ch.logger.Error("Failed to apply post-search filters", zap.Error(err))
			return nil, err
		}
	}

	// Enforce global limit for multi-channel search after filtering, and set a simple cursor if more may exist
	if len(params.channels) > 0 {
		hadMore := false
		if params.limit > 0 && len(allMessages) > params.limit {
			allMessages = allMessages[:params.limit]
			hadMore = true
		}
		messages := ch.convertMessagesFromSearch(allMessages)
		if hadMore && len(messages) > 0 {
			nextCursor := fmt.Sprintf("page:%d", params.page+1)
			messages[len(messages)-1].Cursor = base64.StdEncoding.EncodeToString([]byte(nextCursor))
		}
		return marshalMessagesToCSV(messages)
	}
	messages := ch.convertMessagesFromSearch(allMessages)
	return marshalMessagesToCSV(messages)
}

// applyPostSearchFilters filters messages based on day of week, hour range, and thread reply count
func (ch *ConversationsHandler) applyPostSearchFilters(ctx context.Context, messages []slack.SearchMessage, params *searchParams) ([]slack.SearchMessage, error) {
	var filtered []slack.SearchMessage

	// Guardrail: cap the number of expensive thread lookups to avoid rate limits
	maxLookups := params.limit
	if maxLookups <= 0 || maxLookups > 200 {
		maxLookups = 200
	}
	lookups := 0

	for _, msg := range messages {
		// Check day of week filter
		if params.dayOfWeek != "" {
			matches, err := messageMatchesDayOfWeek(msg.Timestamp, params.dayOfWeek)
			if err != nil {
				ch.logger.Warn("Failed to check day of week for message", zap.String("ts", msg.Timestamp), zap.Error(err))
				continue
			}
			if !matches {
				continue
			}
		}

		// Check hour range filter
		if params.hourRangeStart != 0 || params.hourRangeEnd != 0 {
			matches, err := messageMatchesHourRange(msg.Timestamp, params.hourRangeStart, params.hourRangeEnd)
			if err != nil {
				ch.logger.Warn("Failed to check hour range for message", zap.String("ts", msg.Timestamp), zap.Error(err))
				continue
			}
			if !matches {
				continue
			}
		}

		// Check thread reply count filter
		if params.minThreadReplies > 0 {
			if lookups >= maxLookups {
				ch.logger.Warn("Reached max thread metadata lookups; results may be truncated for minThreadReplies filter",
					zap.Int("limit", maxLookups),
				)
				break
			}

			channelID := msg.Channel.ID
			replyCount, err := ch.getThreadReplyCount(ctx, channelID, msg.Timestamp)
			lookups++
			if err != nil {
				ch.logger.Warn("Failed to get thread reply count", zap.String("channel", channelID), zap.String("ts", msg.Timestamp), zap.Error(err))
				continue
			}
			if replyCount < params.minThreadReplies {
				continue
			}
		}

		filtered = append(filtered, msg)
	}

	return filtered, nil
}

// getThreadReplyCount fetches the reply count for a message in a thread
func (ch *ConversationsHandler) getThreadReplyCount(ctx context.Context, channelID string, threadTs string) (int, error) {
	// Use GetConversationRepliesContext to get thread info
	replies, _, _, err := ch.apiProvider.Slack().GetConversationRepliesContext(ctx,
		&slack.GetConversationRepliesParameters{
			ChannelID: channelID,
			Timestamp: threadTs,
			Limit:     1, // We only need to check reply_count
		},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get conversation replies: %v", err)
	}

	if len(replies) > 0 {
		// Prefer the reply count provided by Slack on the parent message, if available
		if replies[0].ReplyCount > 0 {
			return replies[0].ReplyCount, nil
		}
		// Fallback: with Limit=1, only the parent is returned, so we cannot infer replies reliably
	}

	return 0, nil
}

func isChannelAllowed(channel string) bool {
	config := os.Getenv("SLACK_MCP_ADD_MESSAGE_TOOL")
	if config == "" || config == "true" || config == "1" {
		return true
	}
	items := strings.Split(config, ",")
	isNegated := strings.HasPrefix(strings.TrimSpace(items[0]), "!")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if isNegated {
			if strings.TrimPrefix(item, "!") == channel {
				return false
			}
		} else {
			if item == channel {
				return true
			}
		}
	}
	return !isNegated
}

func (ch *ConversationsHandler) convertMessagesFromHistory(slackMessages []slack.Message, channel string, includeActivity bool) []Message {
	usersMap := ch.apiProvider.ProvideUsersMap()
	var messages []Message
	warn := false

	for _, msg := range slackMessages {
		if (msg.SubType != "" && msg.SubType != "bot_message") && !includeActivity {
			continue
		}

		userName, realName, ok := getUserInfo(msg.User, usersMap.Users)

		if !ok && msg.SubType == "bot_message" {
			userName, realName, ok = getBotInfo(msg.Username)
		}

		if !ok {
			warn = true
		}

		timestamp, err := text.TimestampToIsoRFC3339(msg.Timestamp)
		if err != nil {
			ch.logger.Error("Failed to convert timestamp to RFC3339", zap.Error(err))
			continue
		}

		msgText := msg.Text + text.AttachmentsTo2CSV(msg.Text, msg.Attachments)

		var reactionParts []string
		for _, r := range msg.Reactions {
			reactionParts = append(reactionParts, fmt.Sprintf("%s:%d", r.Name, r.Count))
		}
		reactionsString := strings.Join(reactionParts, "|")

		messages = append(messages, Message{
			MsgID:     msg.Timestamp,
			UserID:    msg.User,
			UserName:  userName,
			RealName:  realName,
			Text:      text.ProcessText(msgText),
			Channel:   channel,
			ThreadTs:  msg.ThreadTimestamp,
			Time:      timestamp,
			Reactions: reactionsString,
		})
	}

	if ready, err := ch.apiProvider.IsReady(); !ready {
		if warn && errors.Is(err, provider.ErrUsersNotReady) {
			ch.logger.Warn(
				"WARNING: Slack users sync is not ready yet, you may experience some limited functionality and see UIDs instead of resolved names as well as unable to query users by their @handles. Users sync is part of channels sync and operations on channels depend on users collection (IM, MPIM). Please wait until users are synced and try again",
				zap.Error(err),
			)
		}
	}
	return messages
}

func (ch *ConversationsHandler) convertMessagesFromSearch(slackMessages []slack.SearchMessage) []Message {
	usersMap := ch.apiProvider.ProvideUsersMap()
	var messages []Message
	warn := false

	for _, msg := range slackMessages {
		userName, realName, ok := getUserInfo(msg.User, usersMap.Users)

		if !ok && msg.User == "" && msg.Username != "" {
			userName, realName, ok = getBotInfo(msg.Username)
		} else if !ok {
			warn = true
		}

		threadTs, _ := extractThreadTS(msg.Permalink)

		timestamp, err := text.TimestampToIsoRFC3339(msg.Timestamp)
		if err != nil {
			ch.logger.Error("Failed to convert timestamp to RFC3339", zap.Error(err))
			continue
		}

		msgText := msg.Text + text.AttachmentsTo2CSV(msg.Text, msg.Attachments)

		messages = append(messages, Message{
			MsgID:     msg.Timestamp,
			UserID:    msg.User,
			UserName:  userName,
			RealName:  realName,
			Text:      text.ProcessText(msgText),
			Channel:   fmt.Sprintf("#%s", msg.Channel.Name),
			ThreadTs:  threadTs,
			Time:      timestamp,
			Reactions: "",
		})
	}

	if ready, err := ch.apiProvider.IsReady(); !ready {
		if warn && errors.Is(err, provider.ErrUsersNotReady) {
			ch.logger.Warn(
				"Slack users sync not ready; you may see raw UIDs instead of names and lose some functionality.",
				zap.Error(err),
			)
		}
	}
	return messages
}

func (ch *ConversationsHandler) parseParamsToolConversations(request mcp.CallToolRequest) (*conversationParams, error) {
	channel := request.GetString("channel_id", "")
	if channel == "" {
		ch.logger.Error("channel_id missing in conversations params")
		return nil, errors.New("channel_id must be a string")
	}

	limit := request.GetString("limit", "")
	cursor := request.GetString("cursor", "")
	activity := request.GetBool("include_activity_messages", false)

	var (
		paramLimit  int
		paramOldest string
		paramLatest string
		err         error
	)
	if strings.HasSuffix(limit, "d") || strings.HasSuffix(limit, "w") || strings.HasSuffix(limit, "m") {
		paramLimit, paramOldest, paramLatest, err = limitByExpression(limit, defaultConversationsExpressionLimit)
		if err != nil {
			ch.logger.Error("Invalid duration limit", zap.String("limit", limit), zap.Error(err))
			return nil, err
		}
	} else if cursor == "" {
		paramLimit, err = limitByNumeric(limit, defaultConversationsNumericLimit)
		if err != nil {
			ch.logger.Error("Invalid numeric limit", zap.String("limit", limit), zap.Error(err))
			return nil, err
		}
	}

	if strings.HasPrefix(channel, "#") || strings.HasPrefix(channel, "@") {
		if ready, err := ch.apiProvider.IsReady(); !ready {
			if errors.Is(err, provider.ErrUsersNotReady) {
				ch.logger.Warn(
					"WARNING: Slack users sync is not ready yet, you may experience some limited functionality and see UIDs instead of resolved names as well as unable to query users by their @handles. Users sync is part of channels sync and operations on channels depend on users collection (IM, MPIM). Please wait until users are synced and try again",
					zap.Error(err),
				)
			}
			if errors.Is(err, provider.ErrChannelsNotReady) {
				ch.logger.Warn(
					"WARNING: Slack channels sync is not ready yet, you may experience some limited functionality and be able to request conversation only by Channel ID, not by its name. Please wait until channels are synced and try again.",
					zap.Error(err),
				)
			}
			return nil, fmt.Errorf("channel %q not found in empty cache", channel)
		}
		channelsMaps := ch.apiProvider.ProvideChannelsMaps()
		chn, ok := channelsMaps.ChannelsInv[channel]
		if !ok {
			ch.logger.Error("Channel not found in synced cache", zap.String("channel", channel))
			return nil, fmt.Errorf("channel %q not found in synced cache. Try to remove old cache file and restart MCP Server", channel)
		}
		channel = channelsMaps.Channels[chn].ID
	}

	return &conversationParams{
		channel:  channel,
		limit:    paramLimit,
		oldest:   paramOldest,
		latest:   paramLatest,
		cursor:   cursor,
		activity: activity,
	}, nil
}

func (ch *ConversationsHandler) parseParamsToolAddMessage(request mcp.CallToolRequest) (*addMessageParams, error) {
	toolConfig := os.Getenv("SLACK_MCP_ADD_MESSAGE_TOOL")
	if toolConfig == "" {
		ch.logger.Error("Add-message tool disabled by default")
		return nil, errors.New(
			"by default, the conversations_add_message tool is disabled to guard Slack workspaces against accidental spamming." +
				"To enable it, set the SLACK_MCP_ADD_MESSAGE_TOOL environment variable to true, 1, or comma separated list of channels" +
				"to limit where the MCP can post messages, e.g. 'SLACK_MCP_ADD_MESSAGE_TOOL=C1234567890,D0987654321', 'SLACK_MCP_ADD_MESSAGE_TOOL=!C1234567890'" +
				"to enable all except one or 'SLACK_MCP_ADD_MESSAGE_TOOL=true' for all channels and DMs",
		)
	}

	channel := request.GetString("channel_id", "")
	if channel == "" {
		ch.logger.Error("channel_id missing in add-message params")
		return nil, errors.New("channel_id must be a string")
	}
	if strings.HasPrefix(channel, "#") || strings.HasPrefix(channel, "@") {
		channelsMaps := ch.apiProvider.ProvideChannelsMaps()
		chn, ok := channelsMaps.ChannelsInv[channel]
		if !ok {
			ch.logger.Error("Channel not found", zap.String("channel", channel))
			return nil, fmt.Errorf("channel %q not found", channel)
		}
		channel = channelsMaps.Channels[chn].ID
	}
	if !isChannelAllowed(channel) {
		ch.logger.Warn("Add-message tool not allowed for channel", zap.String("channel", channel), zap.String("policy", toolConfig))
		return nil, fmt.Errorf("conversations_add_message tool is not allowed for channel %q, applied policy: %s", channel, toolConfig)
	}

	threadTs := request.GetString("thread_ts", "")
	if threadTs != "" && !strings.Contains(threadTs, ".") {
		ch.logger.Error("Invalid thread_ts format", zap.String("thread_ts", threadTs))
		return nil, errors.New("thread_ts must be a valid timestamp in format 1234567890.123456")
	}

	msgText := request.GetString("payload", "")
	if msgText == "" {
		ch.logger.Error("Message text missing")
		return nil, errors.New("text must be a string")
	}

	contentType := request.GetString("content_type", "text/markdown")
	if contentType != "text/plain" && contentType != "text/markdown" {
		ch.logger.Error("Invalid content_type", zap.String("content_type", contentType))
		return nil, errors.New("content_type must be either 'text/plain' or 'text/markdown'")
	}

	return &addMessageParams{
		channel:     channel,
		threadTs:    threadTs,
		text:        msgText,
		contentType: contentType,
	}, nil
}

// parseDateRangeFormat converts formats like "30d", "120d", "1y" to a date string
func parseDateRangeFormat(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	if s == "" {
		return "", nil
	}

	// Check for time-based formats
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		dayCount, err := strconv.Atoi(days)
		if err != nil || dayCount <= 0 {
			return "", fmt.Errorf("invalid day format: %s", s)
		}
		// Calculate date N days ago
		pastDate := time.Now().UTC().AddDate(0, 0, -dayCount)
		return pastDate.Format("2006-01-02"), nil
	}

	if strings.HasSuffix(s, "y") {
		years := strings.TrimSuffix(s, "y")
		yearCount, err := strconv.Atoi(years)
		if err != nil || yearCount <= 0 {
			return "", fmt.Errorf("invalid year format: %s", s)
		}
		// Calculate date N years ago
		pastDate := time.Now().UTC().AddDate(-yearCount, 0, 0)
		return pastDate.Format("2006-01-02"), nil
	}

	// Not a time-based format, return as-is for standard date parsing
	return s, nil
}

// parseHourRange parses "HH:MM-HH:MM" format and returns start and end hours
func parseHourRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}

	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid hour range format: %s, expected HH:MM-HH:MM", s)
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	startTimeParts := strings.Split(startStr, ":")
	if len(startTimeParts) != 2 {
		return 0, 0, fmt.Errorf("invalid start time format: %s, expected HH:MM", startStr)
	}

	endTimeParts := strings.Split(endStr, ":")
	if len(endTimeParts) != 2 {
		return 0, 0, fmt.Errorf("invalid end time format: %s, expected HH:MM", endStr)
	}

	startHour, err := strconv.Atoi(startTimeParts[0])
	if err != nil || startHour < 0 || startHour > 23 {
		return 0, 0, fmt.Errorf("invalid start hour: %s, must be 0-23", startTimeParts[0])
	}

	endHour, err := strconv.Atoi(endTimeParts[0])
	if err != nil || endHour < 0 || endHour > 23 {
		return 0, 0, fmt.Errorf("invalid end hour: %s, must be 0-23", endTimeParts[0])
	}

	return startHour, endHour, nil
}

// validateDayOfWeek validates day of week string
func validateDayOfWeek(day string) (string, error) {
	day = strings.ToLower(strings.TrimSpace(day))
	if day == "" {
		return "", nil
	}

	validDays := map[string]bool{
		"monday":    true,
		"tuesday":   true,
		"wednesday": true,
		"thursday":  true,
		"friday":    true,
		"saturday":  true,
		"sunday":    true,
	}

	if !validDays[day] {
		return "", fmt.Errorf("invalid day of week: %s", day)
	}

	return day, nil
}

// messageMatchesDayOfWeek checks if message timestamp matches the specified day of week
func messageMatchesDayOfWeek(timestamp string, targetDay string) (bool, error) {
	if targetDay == "" {
		return true, nil
	}

	// Parse the message timestamp (should be in format like "2023-10-15T10:30:00Z" from ISO RFC3339)
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// Try unix timestamp format (seconds.microseconds)
		parts := strings.Split(timestamp, ".")
		if len(parts) > 0 {
			unixSec, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return false, fmt.Errorf("cannot parse message timestamp: %s", timestamp)
			}
			t = time.Unix(unixSec, 0).UTC()
		} else {
			return false, fmt.Errorf("cannot parse message timestamp: %s", timestamp)
		}
	}

	dayName := strings.ToLower(t.Weekday().String())
	return dayName == targetDay, nil
}

// messageMatchesHourRange checks if message timestamp falls within the specified UTC hour range
func messageMatchesHourRange(timestamp string, startHour, endHour int) (bool, error) {
	if startHour == 0 && endHour == 0 {
		return true, nil
	}

	// Parse the message timestamp
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// Try unix timestamp format
		parts := strings.Split(timestamp, ".")
		if len(parts) > 0 {
			unixSec, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return false, fmt.Errorf("cannot parse message timestamp: %s", timestamp)
			}
			t = time.Unix(unixSec, 0).UTC()
		} else {
			return false, fmt.Errorf("cannot parse message timestamp: %s", timestamp)
		}
	}

	hour := t.UTC().Hour()

	// Handle range that doesn't wrap around midnight (e.g., 08:00-17:00)
	if startHour <= endHour {
		return hour >= startHour && hour < endHour, nil
	}

	// Handle range that wraps around midnight (e.g., 22:00-06:00)
	return hour >= startHour || hour < endHour, nil
}

func (ch *ConversationsHandler) parseParamsToolSearch(req mcp.CallToolRequest) (*searchParams, error) {
	rawQuery := strings.TrimSpace(req.GetString("search_query", ""))
	freeText, filters := splitQuery(rawQuery)

	if req.GetBool("filter_threads_only", false) {
		addFilter(filters, "is", "thread")
	}

	// Handle multi-channel search
	var channels []string
	if chNamesStr := req.GetString("filter_in_channels", ""); chNamesStr != "" {
		// Parse comma-separated channel names
		chNames := strings.Split(chNamesStr, ",")
		for _, chName := range chNames {
			chName = strings.TrimSpace(chName)
			if chName == "" {
				continue
			}
			f, err := ch.paramFormatChannelForSearch(chName)
			if err != nil {
				// Invalid format, skip this channel
				ch.logger.Warn("Invalid channel format, skipping", zap.String("filter", chName), zap.Error(err))
				continue
			}
			channels = append(channels, f)
		}
	} else if chName := req.GetString("filter_in_channel", ""); chName != "" {
		f, err := ch.paramFormatChannelForSearch(chName)
		if err != nil {
			// Invalid format, return error
			ch.logger.Error("Invalid channel filter", zap.String("filter", chName), zap.Error(err))
			return nil, err
		}
		addFilter(filters, "in", f)
	} else if im := req.GetString("filter_in_im_or_mpim", ""); im != "" {
		f, err := ch.paramFormatUser(im)
		if err != nil {
			ch.logger.Error("Invalid IM/MPIM filter", zap.String("filter", im), zap.Error(err))
			return nil, err
		}
		addFilter(filters, "in", f)
	}

	if with := req.GetString("filter_users_with", ""); with != "" {
		f, err := ch.paramFormatUser(with)
		if err != nil {
			ch.logger.Error("Invalid with-user filter", zap.String("filter", with), zap.Error(err))
			return nil, err
		}
		addFilter(filters, "with", f)
	}
	if from := req.GetString("filter_users_from", ""); from != "" {
		f, err := ch.paramFormatUser(from)
		if err != nil {
			ch.logger.Error("Invalid from-user filter", zap.String("filter", from), zap.Error(err))
			return nil, err
		}
		addFilter(filters, "from", f)
	}

	// Handle date range formats like "30d", "120d", "1y"
	dateAfter := req.GetString("filter_date_after", "")
	if dateAfter != "" {
		convertedDate, err := parseDateRangeFormat(dateAfter)
		if err != nil {
			ch.logger.Error("Invalid date range format", zap.String("filter_date_after", dateAfter), zap.Error(err))
			return nil, err
		}
		dateAfter = convertedDate
	}

	dateMap, err := buildDateFilters(
		req.GetString("filter_date_before", ""),
		dateAfter,
		req.GetString("filter_date_on", ""),
		req.GetString("filter_date_during", ""),
	)
	if err != nil {
		ch.logger.Error("Invalid date filters", zap.Error(err))
		return nil, err
	}
	for key, val := range dateMap {
		addFilter(filters, key, val)
	}

	// Parse new filter parameters
	minThreadReplies := req.GetInt("filter_min_thread_replies", 0)
	if minThreadReplies < 0 {
		ch.logger.Error("Invalid minimum thread replies", zap.Int("value", minThreadReplies))
		return nil, fmt.Errorf("filter_min_thread_replies must be >= 0")
	}

	dayOfWeek := req.GetString("filter_day_of_week", "")
	if dayOfWeek != "" {
		dayOfWeek, err = validateDayOfWeek(dayOfWeek)
		if err != nil {
			ch.logger.Error("Invalid day of week", zap.String("filter_day_of_week", dayOfWeek), zap.Error(err))
			return nil, err
		}
	}

	hourRangeStart, hourRangeEnd := 0, 0
	if hourRange := req.GetString("filter_hour_range", ""); hourRange != "" {
		hourRangeStart, hourRangeEnd, err = parseHourRange(hourRange)
		if err != nil {
			ch.logger.Error("Invalid hour range", zap.String("filter_hour_range", hourRange), zap.Error(err))
			return nil, err
		}
	}

	// Determine if post-search filtering is needed
	postSearchFilters := minThreadReplies > 0 || dayOfWeek != "" || hourRangeStart != 0 || hourRangeEnd != 0

	finalQuery := buildQuery(freeText, filters)
	limit := req.GetInt("limit", 100)
	cursor := req.GetString("cursor", "")

	var (
		page          int
		decodedCursor []byte
	)
	if cursor != "" {
		decodedCursor, err = base64.StdEncoding.DecodeString(cursor)
		if err != nil {
			ch.logger.Error("Invalid cursor decoding", zap.String("cursor", cursor), zap.Error(err))
			return nil, fmt.Errorf("invalid cursor: %v", err)
		}
		parts := strings.Split(string(decodedCursor), ":")
		if len(parts) != 2 {
			ch.logger.Error("Invalid cursor format", zap.String("cursor", cursor))
			return nil, fmt.Errorf("invalid cursor: %v", cursor)
		}
		page, err = strconv.Atoi(parts[1])
		if err != nil || page < 1 {
			ch.logger.Error("Invalid cursor page", zap.String("cursor", cursor), zap.Error(err))
			return nil, fmt.Errorf("invalid cursor page: %v", err)
		}
	} else {
		page = 1
	}

	ch.logger.Debug("Search parameters built",
		zap.String("query", finalQuery),
		zap.Int("limit", limit),
		zap.Int("page", page),
		zap.Strings("channels", channels),
		zap.Int("minThreadReplies", minThreadReplies),
		zap.String("dayOfWeek", dayOfWeek),
		zap.Ints("hourRange", []int{hourRangeStart, hourRangeEnd}),
	)
	return &searchParams{
		query:             finalQuery,
		limit:             limit,
		page:              page,
		channels:          channels,
		minThreadReplies:  minThreadReplies,
		dayOfWeek:         dayOfWeek,
		hourRangeStart:    hourRangeStart,
		hourRangeEnd:      hourRangeEnd,
		postSearchFilters: postSearchFilters,
	}, nil
}

func (ch *ConversationsHandler) paramFormatUser(raw string) (string, error) {
	users := ch.apiProvider.ProvideUsersMap()
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "U") {
		u, ok := users.Users[raw]
		if !ok {

			return "", fmt.Errorf("user %q not found", raw)
		}
		return fmt.Sprintf("<@%s>", u.ID), nil
	}
	if strings.HasPrefix(raw, "<@") {
		raw = raw[2:]
	}
	if strings.HasPrefix(raw, "@") {
		raw = raw[1:]
	}
	uid, ok := users.UsersInv[raw]
	if !ok {
		return "", fmt.Errorf("user %q not found", raw)
	}
	return fmt.Sprintf("<@%s>", uid), nil
}

func (ch *ConversationsHandler) paramFormatChannel(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	cms := ch.apiProvider.ProvideChannelsMaps()
	if strings.HasPrefix(raw, "#") {
		if id, ok := cms.ChannelsInv[raw]; ok {
			return cms.Channels[id].Name, nil
		}

		return "", fmt.Errorf("channel %q not found", raw)
	}
	// Handle both C (standard channels) and G (private groups/channels) prefixes
	if strings.HasPrefix(raw, "C") || strings.HasPrefix(raw, "G") {
		if chn, ok := cms.Channels[raw]; ok {
			return chn.Name, nil
		}
		return "", fmt.Errorf("channel %q not found", raw)
	}
	return "", fmt.Errorf("invalid channel format: %q", raw)
}

// paramFormatChannelForSearch attempts to resolve channel name from cache, but falls back
// to using the name directly if cache isn't ready or channel not found (Slack search can handle names)
func (ch *ConversationsHandler) paramFormatChannelForSearch(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	
	// Check if cache is ready
	ready, _ := ch.apiProvider.IsReady()
	if !ready {
		// Cache not ready, return the name as-is (Slack search can handle it)
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "C") || strings.HasPrefix(raw, "G") {
			return raw, nil
		}
		return "", fmt.Errorf("cache not ready and invalid channel format: %q", raw)
	}
	
	// Try to resolve from cache
	cms := ch.apiProvider.ProvideChannelsMaps()
	if strings.HasPrefix(raw, "#") {
		if id, ok := cms.ChannelsInv[raw]; ok {
			return cms.Channels[id].Name, nil
		}
		// Channel not in cache, but return name anyway for search
		return raw, nil
	}
	// Handle both C (standard channels) and G (private groups/channels) prefixes
	if strings.HasPrefix(raw, "C") || strings.HasPrefix(raw, "G") {
		if chn, ok := cms.Channels[raw]; ok {
			return chn.Name, nil
		}
		// Channel ID not in cache, but return it anyway for search
		return raw, nil
	}
	return "", fmt.Errorf("invalid channel format: %q", raw)
}

func marshalMessagesToCSV(messages []Message) (*mcp.CallToolResult, error) {
	csvBytes, err := gocsv.MarshalBytes(&messages)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(csvBytes)), nil
}

func getUserInfo(userID string, usersMap map[string]slack.User) (userName, realName string, ok bool) {
	if u, ok := usersMap[userID]; ok {
		return u.Name, u.RealName, true
	}
	return userID, userID, false
}

func getBotInfo(botID string) (userName, realName string, ok bool) {
	return botID, botID, true
}

func limitByNumeric(limit string, defaultLimit int) (int, error) {
	if limit == "" {
		return defaultLimit, nil
	}
	n, err := strconv.Atoi(limit)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric limit: %q", limit)
	}
	return n, nil
}

func limitByExpression(limit, defaultLimit string) (slackLimit int, oldest, latest string, err error) {
	if limit == "" {
		limit = defaultLimit
	}
	if len(limit) < 2 {
		return 0, "", "", fmt.Errorf("invalid duration limit %q: too short", limit)
	}
	suffix := limit[len(limit)-1]
	numStr := limit[:len(limit)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 {
		return 0, "", "", fmt.Errorf("invalid duration limit %q: must be a positive integer followed by 'd', 'w', or 'm'", limit)
	}
	now := time.Now()
	loc := now.Location()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	var oldestTime time.Time
	switch suffix {
	case 'd':
		oldestTime = startOfToday.AddDate(0, 0, -n+1)
	case 'w':
		oldestTime = startOfToday.AddDate(0, 0, -n*7+1)
	case 'm':
		oldestTime = startOfToday.AddDate(0, -n, 0)
	default:
		return 0, "", "", fmt.Errorf("invalid duration limit %q: must end in 'd', 'w', or 'm'", limit)
	}
	latest = fmt.Sprintf("%d.000000", now.Unix())
	oldest = fmt.Sprintf("%d.000000", oldestTime.Unix())
	return 100, oldest, latest, nil
}

func extractThreadTS(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	return u.Query().Get("thread_ts"), nil
}

func parseFlexibleDate(dateStr string) (time.Time, string, error) {
	dateStr = strings.TrimSpace(dateStr)
	standardFormats := []string{
		"2006-01-02",      // YYYY-MM-DD
		"2006/01/02",      // YYYY/MM/DD
		"01-02-2006",      // MM-DD-YYYY
		"01/02/2006",      // MM/DD/YYYY
		"02-01-2006",      // DD-MM-YYYY
		"02/01/2006",      // DD/MM/YYYY
		"Jan 2, 2006",     // Jan 2, 2006
		"January 2, 2006", // January 2, 2006
		"2 Jan 2006",      // 2 Jan 2006
		"2 January 2006",  // 2 January 2006
	}
	for _, fmtStr := range standardFormats {
		if t, err := time.Parse(fmtStr, dateStr); err == nil {
			return t, t.Format("2006-01-02"), nil
		}
	}

	monthMap := map[string]int{
		"january": 1, "jan": 1,
		"february": 2, "feb": 2,
		"march": 3, "mar": 3,
		"april": 4, "apr": 4,
		"may":  5,
		"june": 6, "jun": 6,
		"july": 7, "jul": 7,
		"august": 8, "aug": 8,
		"september": 9, "sep": 9, "sept": 9,
		"october": 10, "oct": 10,
		"november": 11, "nov": 11,
		"december": 12, "dec": 12,
	}

	// Month-Year patterns
	monthYear := regexp.MustCompile(`^(\d{4})\s+([A-Za-z]+)$|^([A-Za-z]+)\s+(\d{4})$`)
	if m := monthYear.FindStringSubmatch(dateStr); m != nil {
		var year int
		var monStr string
		if m[1] != "" && m[2] != "" {
			year, _ = strconv.Atoi(m[1])
			monStr = strings.ToLower(m[2])
		} else {
			year, _ = strconv.Atoi(m[4])
			monStr = strings.ToLower(m[3])
		}
		if mon, ok := monthMap[monStr]; ok {
			t := time.Date(year, time.Month(mon), 1, 0, 0, 0, 0, time.UTC)
			return t, t.Format("2006-01-02"), nil
		}
	}

	// Day-Month-Year and Month-Day-Year patterns
	dmy1 := regexp.MustCompile(`^(\d{1,2})[-\s]+([A-Za-z]+)[-\s]+(\d{4})$`)
	if m := dmy1.FindStringSubmatch(dateStr); m != nil {
		day, _ := strconv.Atoi(m[1])
		year, _ := strconv.Atoi(m[3])
		monStr := strings.ToLower(m[2])
		if mon, ok := monthMap[monStr]; ok {
			t := time.Date(year, time.Month(mon), day, 0, 0, 0, 0, time.UTC)
			if t.Day() == day {
				return t, t.Format("2006-01-02"), nil
			}
		}
	}
	mdy := regexp.MustCompile(`^([A-Za-z]+)[-\s]+(\d{1,2})[-\s]+(\d{4})$`)
	if m := mdy.FindStringSubmatch(dateStr); m != nil {
		monStr := strings.ToLower(m[1])
		day, _ := strconv.Atoi(m[2])
		year, _ := strconv.Atoi(m[3])
		if mon, ok := monthMap[monStr]; ok {
			t := time.Date(year, time.Month(mon), day, 0, 0, 0, 0, time.UTC)
			if t.Day() == day {
				return t, t.Format("2006-01-02"), nil
			}
		}
	}
	ymd := regexp.MustCompile(`^(\d{4})[-\s]+([A-Za-z]+)[-\s]+(\d{1,2})$`)
	if m := ymd.FindStringSubmatch(dateStr); m != nil {
		year, _ := strconv.Atoi(m[1])
		monStr := strings.ToLower(m[2])
		day, _ := strconv.Atoi(m[3])
		if mon, ok := monthMap[monStr]; ok {
			t := time.Date(year, time.Month(mon), day, 0, 0, 0, 0, time.UTC)
			if t.Day() == day {
				return t, t.Format("2006-01-02"), nil
			}
		}
	}

	lower := strings.ToLower(dateStr)
	now := time.Now().UTC()
	switch lower {
	case "today":
		t := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return t, t.Format("2006-01-02"), nil
	case "yesterday":
		t := now.AddDate(0, 0, -1)
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return t, t.Format("2006-01-02"), nil
	case "tomorrow":
		t := now.AddDate(0, 0, 1)
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return t, t.Format("2006-01-02"), nil
	}

	daysAgo := regexp.MustCompile(`^(\d+)\s+days?\s+ago$`)
	if m := daysAgo.FindStringSubmatch(lower); m != nil {
		days, _ := strconv.Atoi(m[1])
		t := now.AddDate(0, 0, -days)
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		return t, t.Format("2006-01-02"), nil
	}

	return time.Time{}, "", fmt.Errorf("unable to parse date: %s", dateStr)
}

func buildDateFilters(before, after, on, during string) (map[string]string, error) {
	out := make(map[string]string)
	if on != "" {
		if during != "" || before != "" || after != "" {
			return nil, fmt.Errorf("'on' cannot be combined with other date filters")
		}
		_, normalized, err := parseFlexibleDate(on)
		if err != nil {
			return nil, fmt.Errorf("invalid 'on' date: %v", err)
		}
		out["on"] = normalized
		return out, nil
	}
	if during != "" {
		if before != "" || after != "" {
			return nil, fmt.Errorf("'during' cannot be combined with 'before' or 'after'")
		}
		_, normalized, err := parseFlexibleDate(during)
		if err != nil {
			return nil, fmt.Errorf("invalid 'during' date: %v", err)
		}
		out["during"] = normalized
		return out, nil
	}
	if after != "" {
		_, normalized, err := parseFlexibleDate(after)
		if err != nil {
			return nil, fmt.Errorf("invalid 'after' date: %v", err)
		}
		out["after"] = normalized
	}
	if before != "" {
		_, normalized, err := parseFlexibleDate(before)
		if err != nil {
			return nil, fmt.Errorf("invalid 'before' date: %v", err)
		}
		out["before"] = normalized
	}
	if after != "" && before != "" {
		a, _, _ := parseFlexibleDate(after)
		b, _, _ := parseFlexibleDate(before)
		if a.After(b) {
			return nil, fmt.Errorf("'after' date is after 'before' date")
		}
	}
	return out, nil
}

func isFilterKey(key string) bool {
	_, ok := validFilterKeys[strings.ToLower(key)]
	return ok
}

func splitQuery(q string) (freeText []string, filters map[string][]string) {
	filters = make(map[string][]string)
	for _, tok := range strings.Fields(q) {
		parts := strings.SplitN(tok, ":", 2)
		if len(parts) == 2 && isFilterKey(parts[0]) {
			key := strings.ToLower(parts[0])
			filters[key] = append(filters[key], parts[1])
		} else {
			freeText = append(freeText, tok)
		}
	}
	return
}

func addFilter(filters map[string][]string, key, val string) {
	for _, existing := range filters[key] {
		if existing == val {
			return
		}
	}
	filters[key] = append(filters[key], val)
}

func buildQuery(freeText []string, filters map[string][]string) string {
	var out []string
	out = append(out, freeText...)
	for _, key := range []string{"is", "in", "from", "with", "before", "after", "on", "during"} {
		for _, val := range filters[key] {
			out = append(out, fmt.Sprintf("%s:%s", key, val))
		}
	}
	return strings.Join(out, " ")
}

// ConversationsGetMessageContextHandler gets messages before and after a specific message
func (ch *ConversationsHandler) ConversationsGetMessageContextHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsGetMessageContextHandler called", zap.Any("params", request.Params))

	channelID := request.GetString("channel_id", "")
	if channelID == "" {
		return nil, errors.New("channel_id is required")
	}

	messageTs := request.GetString("message_ts", "")
	if messageTs == "" {
		return nil, errors.New("message_ts is required")
	}

	beforeCount := request.GetInt("before_count", 5)
	afterCount := request.GetInt("after_count", 5)
	includeThread := request.GetBool("include_thread", true)

	// Parse timestamp to get numeric value
	tsParts := strings.Split(messageTs, ".")
	if len(tsParts) != 2 {
		return nil, fmt.Errorf("invalid message_ts format: %s, expected format: 1234567890.123456", messageTs)
	}

	tsSeconds, err := strconv.ParseInt(tsParts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid message_ts seconds: %v", err)
	}

	// Resolve channel name to ID if needed
	if strings.HasPrefix(channelID, "#") || strings.HasPrefix(channelID, "@") {
		if ready, err := ch.apiProvider.IsReady(); !ready {
			if errors.Is(err, provider.ErrChannelsNotReady) {
				return nil, fmt.Errorf("channels cache not ready: %v", err)
			}
		}
		channelsMaps := ch.apiProvider.ProvideChannelsMaps()
		chn, ok := channelsMaps.ChannelsInv[channelID]
		if !ok {
			return nil, fmt.Errorf("channel %q not found", channelID)
		}
		channelID = channelsMaps.Channels[chn].ID
	}

	// Calculate time window around the message
	// We'll fetch messages in a range that should include before_count + after_count messages
	// Estimate 1 minute per message for safety
	windowSeconds := int64((beforeCount + afterCount + 1) * 60)
	if windowSeconds < 300 {
		windowSeconds = 300 // Minimum 5 minutes
	}

	oldestTs := fmt.Sprintf("%d.000000", tsSeconds-windowSeconds)
	latestTs := fmt.Sprintf("%d.999999", tsSeconds+windowSeconds)

	historyParams := slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Oldest:    oldestTs,
		Latest:    latestTs,
		Limit:     beforeCount + afterCount + 1,
		Inclusive: true,
	}

	history, err := ch.apiProvider.Slack().GetConversationHistoryContext(ctx, &historyParams)
	if err != nil {
		ch.logger.Error("GetConversationHistoryContext failed", zap.Error(err))
		return nil, err
	}

	// Find the target message and extract messages before/after
	// Messages come in reverse chronological order (newest first)
	var beforeMessages, targetMessage, afterMessages []slack.Message
	targetFound := false

	for _, msg := range history.Messages {
		if msg.Timestamp == messageTs {
			targetMessage = []slack.Message{msg}
			targetFound = true
			continue
		}

		if !targetFound {
			// Messages after target (newer messages come first in reverse chronological order)
			if len(afterMessages) < afterCount {
				afterMessages = append([]slack.Message{msg}, afterMessages...)
			}
		} else {
			// Messages before target (older messages come after target in reverse chronological order)
			if len(beforeMessages) < beforeCount {
				beforeMessages = append(beforeMessages, msg)
			}
		}
	}

	// Reverse beforeMessages and afterMessages to get chronological order
	for i, j := 0, len(beforeMessages)-1; i < j; i, j = i+1, j-1 {
		beforeMessages[i], beforeMessages[j] = beforeMessages[j], beforeMessages[i]
	}
	for i, j := 0, len(afterMessages)-1; i < j; i, j = i+1, j-1 {
		afterMessages[i], afterMessages[j] = afterMessages[j], afterMessages[i]
	}

	// Combine all messages
	allMessages := append(append(beforeMessages, targetMessage...), afterMessages...)

	if !targetFound && len(allMessages) == 0 {
		return nil, fmt.Errorf("message with timestamp %s not found in channel %s", messageTs, channelID)
	}

	// Include thread replies if requested and message is in a thread
	messages := ch.convertMessagesFromHistory(allMessages, channelID, false)

	if includeThread && len(targetMessage) > 0 && targetMessage[0].ThreadTimestamp == "" {
		// Check if this message has replies (it might be a thread parent)
		replies, _, _, err := ch.apiProvider.Slack().GetConversationRepliesContext(ctx,
			&slack.GetConversationRepliesParameters{
				ChannelID: channelID,
				Timestamp: messageTs,
				Limit:     50,
			})
		if err == nil && len(replies) > 1 {
			// Include thread replies
			threadMessages := ch.convertMessagesFromHistory(replies[1:], channelID, false)
			messages = append(messages, threadMessages...)
		}
	}

	return marshalMessagesToCSV(messages)
}

// ConversationsFindRelatedThreadsHandler finds threads with similar keywords or error patterns
func (ch *ConversationsHandler) ConversationsFindRelatedThreadsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsFindRelatedThreadsHandler called", zap.Any("params", request.Params))

	searchQuery := request.GetString("search_query", "")
	if searchQuery == "" {
		return nil, errors.New("search_query is required")
	}

	channelID := request.GetString("channel_id", "")
	filterDateAfter := request.GetString("filter_date_after", "")
	minThreadReplies := request.GetInt("filter_min_thread_replies", 1)
	limit := request.GetInt("limit", 10)

	// Build search parameters
	args := map[string]interface{}{
		"search_query":             searchQuery,
		"filter_threads_only":      true,
		"filter_min_thread_replies": minThreadReplies,
		"limit":                     limit * 2, // Get more to account for grouping
	}

	if channelID != "" {
		args["filter_in_channel"] = channelID
	}

	if filterDateAfter != "" {
		args["filter_date_after"] = filterDateAfter
	}

	// Build searchParams directly
	params := &searchParams{
		query:             searchQuery,
		limit:             limit * 2,
		page:              1,
		minThreadReplies:  minThreadReplies,
		postSearchFilters: minThreadReplies > 0,
	}

	if channelID != "" {
		chName, err := ch.paramFormatChannel(channelID)
		if err == nil {
			params.channels = []string{chName}
		}
	}

	// Build query with thread filter
	freeText, filters := splitQuery(searchQuery)
	addFilter(filters, "is", "thread")
	if filterDateAfter != "" {
		convertedDate, err := parseDateRangeFormat(filterDateAfter)
		if err == nil {
			dateMap, _ := buildDateFilters("", convertedDate, "", "")
			for key, val := range dateMap {
				addFilter(filters, key, val)
			}
		}
	}
	params.query = buildQuery(freeText, filters)

	// Execute search using internal logic
	return ch.executeSearch(ctx, params)
}

// executeSearch executes a search with the given parameters
func (ch *ConversationsHandler) executeSearch(ctx context.Context, params *searchParams) (*mcp.CallToolResult, error) {
	var allMessages []slack.SearchMessage

	// Handle multi-channel search
	if len(params.channels) > 0 {
		for _, channelName := range params.channels {
			baseQuery := sanitizeRemoveInFilters(params.query)
			queryWithChannel := strings.TrimSpace(baseQuery + " in:" + channelName)

			searchParams := slack.SearchParameters{
				Sort:          slack.DEFAULT_SEARCH_SORT,
				SortDirection: slack.DEFAULT_SEARCH_SORT_DIR,
				Highlight:     false,
				Count:         params.limit,
				Page:          params.page,
			}

			messagesRes, _, err := ch.apiProvider.Slack().SearchContext(ctx, queryWithChannel, searchParams)
			if err != nil {
				ch.logger.Error("Slack SearchContext failed for channel", zap.String("channel", channelName), zap.Error(err))
				return nil, err
			}

			allMessages = append(allMessages, messagesRes.Matches...)
		}

		sort.Slice(allMessages, func(i, j int) bool {
			return allMessages[i].Timestamp > allMessages[j].Timestamp
		})
	} else {
		searchParams := slack.SearchParameters{
			Sort:          slack.DEFAULT_SEARCH_SORT,
			SortDirection: slack.DEFAULT_SEARCH_SORT_DIR,
			Highlight:     false,
			Count:         params.limit,
			Page:          params.page,
		}

		messagesRes, _, err := ch.apiProvider.Slack().SearchContext(ctx, params.query, searchParams)
		if err != nil {
			ch.logger.Error("Slack SearchContext failed", zap.Error(err))
			return nil, err
		}

		allMessages = messagesRes.Matches
	}

	// Apply post-search filters
	if params.postSearchFilters {
		var err error
		allMessages, err = ch.applyPostSearchFilters(ctx, allMessages, params)
		if err != nil {
			ch.logger.Error("Failed to apply post-search filters", zap.Error(err))
			return nil, err
		}
	}

	// Enforce global limit for multi-channel search after filtering
	if len(params.channels) > 0 {
		if params.limit > 0 && len(allMessages) > params.limit {
			allMessages = allMessages[:params.limit]
		}
	}

	messages := ch.convertMessagesFromSearch(allMessages)
	return marshalMessagesToCSV(messages)
}

// ConversationsGetUserTimelineHandler gets all messages from a specific user in a time range
func (ch *ConversationsHandler) ConversationsGetUserTimelineHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsGetUserTimelineHandler called", zap.Any("params", request.Params))

	userID := request.GetString("user_id", "")
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	filterDateAfter := request.GetString("filter_date_after", "")
	if filterDateAfter == "" {
		return nil, errors.New("filter_date_after is required")
	}

	filterDateBefore := request.GetString("filter_date_before", "")
	filterInChannels := request.GetString("filter_in_channels", "")
	limit := request.GetInt("limit", 50)

	// Format user ID for search - paramFormatUser returns <@U123> format, we need just the user ID
	var userIDForSearch string
	if strings.HasPrefix(userID, "U") {
		userIDForSearch = userID
	} else {
		userFormatted, err := ch.paramFormatUser(userID)
		if err != nil {
			return nil, fmt.Errorf("invalid user_id: %v", err)
		}
		// Extract user ID from <@U123> format
		userIDForSearch = strings.TrimPrefix(strings.TrimSuffix(userFormatted, ">"), "<@")
	}

	// Build search parameters
	freeText, filters := splitQuery("")
	userFormatted, err := ch.paramFormatUser(userIDForSearch)
	if err == nil {
		addFilter(filters, "from", userFormatted)
	}

	// Handle date filters
	convertedDateAfter, err := parseDateRangeFormat(filterDateAfter)
	if err == nil && convertedDateAfter != "" {
		dateMap, _ := buildDateFilters(filterDateBefore, convertedDateAfter, "", "")
		for key, val := range dateMap {
			addFilter(filters, key, val)
		}
	}

	query := buildQuery(freeText, filters)
	params := &searchParams{
		query:    query,
		limit:    limit,
		page:     1,
		channels: []string{},
	}

	// Handle channel filter
	if filterInChannels != "" {
		chNames := strings.Split(filterInChannels, ",")
		for _, chName := range chNames {
			chName = strings.TrimSpace(chName)
			if chName == "" {
				continue
			}
			chFormatted, err := ch.paramFormatChannel(chName)
			if err == nil {
				params.channels = append(params.channels, chFormatted)
			}
		}
	}

	return ch.executeSearch(ctx, params)
}

// ThreadAnalysis represents analysis of a thread
type ThreadAnalysis struct {
	ThreadTs            string            `json:"threadTs" csv:"threadTs"`
	Channel             string            `json:"channel" csv:"channel"`
	ParticipantCount    int               `json:"participantCount" csv:"participantCount"`
	MessageCount        int               `json:"messageCount" csv:"messageCount"`
	Participants        string            `json:"participants" csv:"participants"` // CSV of user:count
	Reactions           string            `json:"reactions" csv:"reactions"`       // CSV of reaction:count
	HasResolution       bool              `json:"hasResolution" csv:"hasResolution"`
	ResolutionIndicators string           `json:"resolutionIndicators" csv:"resolutionIndicators"`
	FirstMessageTime    string            `json:"firstMessageTime" csv:"firstMessageTime"`
	LastMessageTime     string            `json:"lastMessageTime" csv:"lastMessageTime"`
	DurationHours       float64           `json:"durationHours" csv:"durationHours"`
}

// ConversationsAnalyzeThreadHandler provides comprehensive thread analysis
func (ch *ConversationsHandler) ConversationsAnalyzeThreadHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsAnalyzeThreadHandler called", zap.Any("params", request.Params))

	channelID := request.GetString("channel_id", "")
	if channelID == "" {
		return nil, errors.New("channel_id is required")
	}

	threadTs := request.GetString("thread_ts", "")
	if threadTs == "" {
		return nil, errors.New("thread_ts is required")
	}

	includeResolutionIndicators := request.GetBool("include_resolution_indicators", true)

	// Resolve channel name to ID if needed
	if strings.HasPrefix(channelID, "#") || strings.HasPrefix(channelID, "@") {
		if ready, err := ch.apiProvider.IsReady(); !ready {
			if errors.Is(err, provider.ErrChannelsNotReady) {
				return nil, fmt.Errorf("channels cache not ready: %v", err)
			}
		}
		channelsMaps := ch.apiProvider.ProvideChannelsMaps()
		chn, ok := channelsMaps.ChannelsInv[channelID]
		if !ok {
			return nil, fmt.Errorf("channel %q not found", channelID)
		}
		channelID = channelsMaps.Channels[chn].ID
	}

	// Get all thread replies
	repliesParams := slack.GetConversationRepliesParameters{
		ChannelID: channelID,
		Timestamp: threadTs,
		Limit:     1000, // Get all replies
	}

	replies, _, _, err := ch.apiProvider.Slack().GetConversationRepliesContext(ctx, &repliesParams)
	if err != nil {
		ch.logger.Error("GetConversationRepliesContext failed", zap.Error(err))
		return nil, err
	}

	if len(replies) == 0 {
		return nil, fmt.Errorf("thread %s not found in channel %s", threadTs, channelID)
	}

	// Analyze thread
	analysis := ch.analyzeThreadParticipants(replies, includeResolutionIndicators)

	// Set channel name
	channelsMaps := ch.apiProvider.ProvideChannelsMaps()
	if chn, ok := channelsMaps.Channels[channelID]; ok {
		analysis.Channel = "#" + chn.Name
	} else {
		analysis.Channel = channelID
	}
	analysis.ThreadTs = threadTs

	// Marshal to CSV
	csvBytes, err := gocsv.MarshalBytes([]ThreadAnalysis{analysis})
	if err != nil {
		return nil, err
	}

	return mcp.NewToolResultText(string(csvBytes)), nil
}

// ConversationsSearchByReactionHandler finds messages with specific reactions
func (ch *ConversationsHandler) ConversationsSearchByReactionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsSearchByReactionHandler called", zap.Any("params", request.Params))

	reactionName := request.GetString("reaction_name", "")
	if reactionName == "" {
		return nil, errors.New("reaction_name is required")
	}

	channelID := request.GetString("channel_id", "")
	filterDateAfter := request.GetString("filter_date_after", "")
	limit := request.GetInt("limit", 20)

	// Resolve channel name to ID if needed
	if channelID != "" {
		if strings.HasPrefix(channelID, "#") || strings.HasPrefix(channelID, "@") {
			if ready, err := ch.apiProvider.IsReady(); !ready {
				if errors.Is(err, provider.ErrChannelsNotReady) {
					return nil, fmt.Errorf("channels cache not ready: %v", err)
				}
			}
			channelsMaps := ch.apiProvider.ProvideChannelsMaps()
			chn, ok := channelsMaps.ChannelsInv[channelID]
			if !ok {
				return nil, fmt.Errorf("channel %q not found", channelID)
			}
			channelID = channelsMaps.Channels[chn].ID
		}
	}

	// Calculate time range
	var oldestTs string
	if filterDateAfter != "" {
		_, normalized, err := parseFlexibleDate(filterDateAfter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter_date_after: %v", err)
		}
		t, _, _ := parseFlexibleDate(normalized)
		oldestTs = fmt.Sprintf("%d.000000", t.Unix())
	} else {
		// Default to last 30 days
		oldestTs = fmt.Sprintf("%d.000000", time.Now().AddDate(0, 0, -30).Unix())
	}

	// Fetch messages from channel(s)
	var allMessages []slack.Message
	if channelID != "" {
		historyParams := slack.GetConversationHistoryParameters{
			ChannelID: channelID,
			Oldest:    oldestTs,
			Limit:     limit * 5, // Fetch more to account for filtering
		}
		history, err := ch.apiProvider.Slack().GetConversationHistoryContext(ctx, &historyParams)
		if err != nil {
			return nil, err
		}
		allMessages = history.Messages
	} else {
		// Note: Searching by reaction across all channels would require fetching all messages
		// and filtering, which is expensive. For now, we'll only support single channel search
		return nil, errors.New("searching by reaction across all channels requires channel_id")
	}

	// Filter messages by reaction
	filteredMessages := ch.filterMessagesByReaction(allMessages, reactionName, limit)

	messages := ch.convertMessagesFromHistory(filteredMessages, channelID, false)
	return marshalMessagesToCSV(messages)
}

// ConversationsFindPatternsHandler searches for similar messages/patterns
func (ch *ConversationsHandler) ConversationsFindPatternsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ch.logger.Debug("ConversationsFindPatternsHandler called", zap.Any("params", request.Params))

	pattern := request.GetString("pattern", "")
	if pattern == "" {
		return nil, errors.New("pattern is required")
	}

	filterInChannels := request.GetString("filter_in_channels", "")
	filterDateAfter := request.GetString("filter_date_after", "")
	exactMatch := request.GetBool("exact_match", false)
	limit := request.GetInt("limit", 50)

	// Build search parameters
	freeText, filters := splitQuery(pattern)

	// Handle date filter
	if filterDateAfter != "" {
		convertedDate, err := parseDateRangeFormat(filterDateAfter)
		if err == nil && convertedDate != "" {
			dateMap, _ := buildDateFilters("", convertedDate, "", "")
			for key, val := range dateMap {
				addFilter(filters, key, val)
			}
		}
	}

	query := buildQuery(freeText, filters)
	params := &searchParams{
		query:    query,
		limit:    limit * 2, // Get more to account for filtering
		page:     1,
		channels: []string{},
	}

	// Handle channel filter
	if filterInChannels != "" {
		chNames := strings.Split(filterInChannels, ",")
		for _, chName := range chNames {
			chName = strings.TrimSpace(chName)
			if chName == "" {
				continue
			}
			chFormatted, err := ch.paramFormatChannel(chName)
			if err == nil {
				params.channels = append(params.channels, chFormatted)
			}
		}
	}

	// Execute search
	result, err := ch.executeSearch(ctx, params)
	if err != nil {
		return nil, err
	}

	// If exact_match is true, we'd need to parse CSV and filter exact matches
	// For now, return search results (Slack search does partial matching)
	if exactMatch {
		ch.logger.Warn("exact_match filtering not yet implemented, returning search results")
	}

	return result, nil
}

// Helper functions

func (ch *ConversationsHandler) analyzeThreadParticipants(replies []slack.Message, includeResolutionIndicators bool) ThreadAnalysis {
	usersMap := ch.apiProvider.ProvideUsersMap()
	participantMap := make(map[string]int)
	reactionMap := make(map[string]int)
	var resolutionIndicators []string

	var firstTime, lastTime time.Time
	firstTS := ""
	lastTS := ""

	resolutionKeywords := []string{"resolved", "fixed", "solved", "done", "completed", "closed"}
	resolutionReactions := []string{"white_check_mark", "check", "heavy_check_mark"}

	for i, msg := range replies {
		// Track participants
		if msg.User != "" {
			participantMap[msg.User]++
		}

		// Track reactions
		for _, reaction := range msg.Reactions {
			reactionMap[reaction.Name] += reaction.Count
			if includeResolutionIndicators {
				for _, resReaction := range resolutionReactions {
					if reaction.Name == resReaction {
						resolutionIndicators = append(resolutionIndicators, fmt.Sprintf("reaction:%s", reaction.Name))
					}
				}
			}
		}

		// Check for resolution keywords
		if includeResolutionIndicators {
			msgText := strings.ToLower(msg.Text)
			for _, keyword := range resolutionKeywords {
				if strings.Contains(msgText, keyword) {
					resolutionIndicators = append(resolutionIndicators, fmt.Sprintf("keyword:%s", keyword))
				}
			}
		}

		// Track timestamps
		tsParts := strings.Split(msg.Timestamp, ".")
		if len(tsParts) == 2 {
			tsSeconds, _ := strconv.ParseInt(tsParts[0], 10, 64)
			msgTime := time.Unix(tsSeconds, 0)
			if i == 0 || msgTime.Before(firstTime) {
				firstTime = msgTime
				firstTS = msg.Timestamp
			}
			if i == 0 || msgTime.After(lastTime) {
				lastTime = msgTime
				lastTS = msg.Timestamp
			}
		}
	}

	// Build participant string
	var participantParts []string
	for userID, count := range participantMap {
		userName, realName, _ := getUserInfo(userID, usersMap.Users)
		displayName := realName
		if displayName == "" {
			displayName = userName
		}
		if displayName == "" {
			displayName = userID
		}
		participantParts = append(participantParts, fmt.Sprintf("%s:%d", displayName, count))
	}

	// Build reaction string
	var reactionParts []string
	for reactionName, count := range reactionMap {
		reactionParts = append(reactionParts, fmt.Sprintf("%s:%d", reactionName, count))
	}

	// Calculate duration
	durationHours := 0.0
	if !firstTime.IsZero() && !lastTime.IsZero() {
		durationHours = lastTime.Sub(firstTime).Hours()
	}

	// Format timestamps
	firstTimeStr := ""
	lastTimeStr := ""
	if firstTS != "" {
		firstTimeStr, _ = text.TimestampToIsoRFC3339(firstTS)
	}
	if lastTS != "" {
		lastTimeStr, _ = text.TimestampToIsoRFC3339(lastTS)
	}

	return ThreadAnalysis{
		ParticipantCount:     len(participantMap),
		MessageCount:         len(replies),
		Participants:         strings.Join(participantParts, "|"),
		Reactions:            strings.Join(reactionParts, "|"),
		HasResolution:        len(resolutionIndicators) > 0,
		ResolutionIndicators: strings.Join(resolutionIndicators, ","),
		FirstMessageTime:     firstTimeStr,
		LastMessageTime:      lastTimeStr,
		DurationHours:        durationHours,
	}
}

func (ch *ConversationsHandler) filterMessagesByReaction(messages []slack.Message, reactionName string, limit int) []slack.Message {
	var filtered []slack.Message
	for _, msg := range messages {
		for _, reaction := range msg.Reactions {
			if reaction.Name == reactionName {
				filtered = append(filtered, msg)
				break
			}
		}
		if len(filtered) >= limit {
			break
		}
	}
	return filtered
}
