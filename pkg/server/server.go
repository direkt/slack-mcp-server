package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/handler"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"github.com/korotovsky/slack-mcp-server/pkg/server/auth"
	"github.com/korotovsky/slack-mcp-server/pkg/text"
	"github.com/korotovsky/slack-mcp-server/pkg/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

type MCPServer struct {
	server *server.MCPServer
	logger *zap.Logger
}

func NewMCPServer(provider *provider.ApiProvider, logger *zap.Logger) *MCPServer {
	s := server.NewMCPServer(
		"Slack MCP Server",
		version.Version,
		server.WithLogging(),
		server.WithRecovery(),
		server.WithToolHandlerMiddleware(buildLoggerMiddleware(logger)),
		server.WithToolHandlerMiddleware(auth.BuildMiddleware(provider.ServerTransport(), logger)),
	)

	conversationsHandler := handler.NewConversationsHandler(provider, logger)

	s.AddTool(mcp.NewTool("conversations_history",
		mcp.WithDescription("Get messages from the channel (or DM) by channel_id, the last row/column in the response is used as 'cursor' parameter for pagination if not empty"),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("    - `channel_id` (string): ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithBoolean("include_activity_messages",
			mcp.Description("If true, the response will include activity messages such as 'channel_join' or 'channel_leave'. Default is boolean false."),
			mcp.DefaultBool(false),
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithString("limit",
			mcp.DefaultString("1d"),
			mcp.Description("Limit of messages to fetch in format of maximum ranges of time (e.g. 1d - 1 day, 1w - 1 week, 30d - 30 days, 90d - 90 days which is a default limit for free tier history) or number of messages (e.g. 50). Must be empty when 'cursor' is provided."),
		),
	), conversationsHandler.ConversationsHistoryHandler)

	s.AddTool(mcp.NewTool("conversations_replies",
		mcp.WithDescription("Get a thread of messages posted to a conversation by channelID and thread_ts, the last row/column in the response is used as 'cursor' parameter for pagination if not empty"),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithString("thread_ts",
			mcp.Required(),
			mcp.Description("Unique identifier of either a thread's parent message or a message in the thread. ts must be the timestamp in format 1234567890.123456 of an existing message with 0 or more replies."),
		),
		mcp.WithBoolean("include_activity_messages",
			mcp.Description("If true, the response will include activity messages such as 'channel_join' or 'channel_leave'. Default is boolean false."),
			mcp.DefaultBool(false),
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithString("limit",
			mcp.DefaultString("1d"),
			mcp.Description("Limit of messages to fetch in format of maximum ranges of time (e.g. 1d - 1 day, 30d - 30 days, 90d - 90 days which is a default limit for free tier history) or number of messages (e.g. 50). Must be empty when 'cursor' is provided."),
		),
	), conversationsHandler.ConversationsRepliesHandler)

	// Register add_message tool only when explicitly enabled for safety
	if cfg := os.Getenv("SLACK_MCP_ADD_MESSAGE_TOOL"); cfg != "" && cfg != "false" && cfg != "0" {
		s.AddTool(mcp.NewTool("conversations_add_message",
			mcp.WithDescription("Add a message to a public channel, private channel, or direct message (DM, or IM) conversation by channel_id and thread_ts."),
			mcp.WithString("channel_id",
				mcp.Required(),
				mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
			),
			mcp.WithString("thread_ts",
				mcp.Description("Unique identifier of either a thread's parent message or a message in the thread_ts must be the timestamp in format 1234567890.123456 of an existing message with 0 or more replies. Optional, if not provided the message will be added to the channel itself, otherwise it will be added to the thread."),
			),
			mcp.WithString("payload",
				mcp.Description("Message payload in specified content_type format. Example: 'Hello, world!' for text/plain or '# Hello, world!' for text/markdown."),
			),
			mcp.WithString("content_type",
				mcp.DefaultString("text/markdown"),
				mcp.Description("Content type of the message. Default is 'text/markdown'. Allowed values: 'text/markdown', 'text/plain'."),
			),
		), conversationsHandler.ConversationsAddMessageHandler)
	}

	s.AddTool(mcp.NewTool("conversations_search_messages",
		mcp.WithDescription("Search messages in a public channel, private channel, or direct message (DM, or IM) conversation using filters. All filters are optional, if not provided then search_query is required."),
		mcp.WithString("search_query",
			mcp.Description("Search query to filter messages. Example: 'marketing report' or full URL of Slack message e.g. 'https://slack.com/archives/C1234567890/p1234567890123456', then the tool will return a single message matching given URL, herewith all other parameters will be ignored."),
		),
		mcp.WithString("filter_in_channel",
			mcp.Description("Filter messages in a specific public/private channel by its ID or name. Example: 'C1234567890', 'G1234567890', or '#general'. If not provided, all channels will be searched."),
		),
		mcp.WithString("filter_in_channels",
			mcp.Description("Filter messages across multiple channels by their IDs or names (comma-separated). Example: '#support,#bugs,#incidents' or 'C123,C456'. Results will be merged and sorted by timestamp. Cannot be used with filter_in_channel."),
		),
		mcp.WithString("filter_in_im_or_mpim",
			mcp.Description("Filter messages in a direct message (DM) or multi-person direct message (MPIM) conversation by its ID or name. Example: 'D1234567890' or '@username_dm'. If not provided, all DMs and MPIMs will be searched."),
		),
		mcp.WithString("filter_users_with",
			mcp.Description("Filter messages with a specific user by their ID or display name in threads and DMs. Example: 'U1234567890' or '@username'. If not provided, all threads and DMs will be searched."),
		),
		mcp.WithString("filter_users_from",
			mcp.Description("Filter messages from a specific user by their ID or display name. Example: 'U1234567890' or '@username'. If not provided, all users will be searched."),
		),
		mcp.WithString("filter_date_before",
			mcp.Description("Filter messages sent before a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_after",
			mcp.Description("Filter messages sent after a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday', 'Today', '30d', '120d', or '1y'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_on",
			mcp.Description("Filter messages sent on a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_during",
			mcp.Description("Filter messages sent during a specific period in format 'YYYY-MM-DD'. Example: 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithBoolean("filter_threads_only",
			mcp.Description("If true, the response will include only messages from threads. Default is boolean false."),
		),
		mcp.WithNumber("filter_min_thread_replies",
			mcp.Description("Filter messages that have at least this many replies in their thread. Example: 5 will return messages that have started threads with 5 or more replies. Useful for finding complex issues."),
		),
		mcp.WithString("filter_day_of_week",
			mcp.Description("Filter messages from a specific day of the week. Example: 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'. Case-insensitive."),
		),
		mcp.WithString("filter_hour_range",
			mcp.Description("Filter messages sent during a specific hour range in UTC. Example: '08:00-17:00' for business hours. Format is 'HH:MM-HH:MM' in 24-hour UTC format."),
		),
		mcp.WithString("cursor",
			mcp.DefaultString(""),
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(20),
			mcp.Description("The maximum number of items to return. Must be an integer between 1 and 100."),
		),
	), conversationsHandler.ConversationsSearchHandler)

	s.AddTool(mcp.NewTool("conversations_get_message_context",
		mcp.WithDescription("Get messages before and after a specific message to understand the conversation flow around an issue."),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithString("message_ts",
			mcp.Required(),
			mcp.Description("Timestamp of the target message in format 1234567890.123456."),
		),
		mcp.WithNumber("before_count",
			mcp.DefaultNumber(5),
			mcp.Description("Number of messages before the target message to include. Default is 5."),
		),
		mcp.WithNumber("after_count",
			mcp.DefaultNumber(5),
			mcp.Description("Number of messages after the target message to include. Default is 5."),
		),
		mcp.WithBoolean("include_thread",
			mcp.DefaultBool(true),
			mcp.Description("If true, include thread replies if the message is a thread parent. Default is true."),
		),
	), conversationsHandler.ConversationsGetMessageContextHandler)

	s.AddTool(mcp.NewTool("conversations_find_related_threads",
		mcp.WithDescription("Find threads that mention similar keywords or error patterns, useful for finding if an issue was discussed before."),
		mcp.WithString("search_query",
			mcp.Required(),
			mcp.Description("Keywords or error message to search for."),
		),
		mcp.WithString("channel_id",
			mcp.Description("Limit search to a specific channel by its ID or name. Example: 'C1234567890' or '#general'. If not provided, all channels will be searched."),
		),
		mcp.WithString("filter_date_after",
			mcp.Description("Only search threads after this date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday', 'Today', '30d', '120d', or '1y'."),
		),
		mcp.WithNumber("filter_min_thread_replies",
			mcp.DefaultNumber(1),
			mcp.Description("Minimum number of replies in thread. Default is 1."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(10),
			mcp.Description("Maximum number of threads to return. Default is 10."),
		),
	), conversationsHandler.ConversationsFindRelatedThreadsHandler)

	s.AddTool(mcp.NewTool("conversations_get_user_timeline",
		mcp.WithDescription("Get all messages from a specific user in a time range, useful for understanding a user's issue history."),
		mcp.WithString("user_id",
			mcp.Required(),
			mcp.Description("User ID or @username. Example: 'U1234567890' or '@username'."),
		),
		mcp.WithString("filter_date_after",
			mcp.Required(),
			mcp.Description("Start date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday', 'Today', '30d', '120d', or '1y'."),
		),
		mcp.WithString("filter_date_before",
			mcp.Description("End date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, defaults to now."),
		),
		mcp.WithString("filter_in_channels",
			mcp.Description("Comma-separated channel names or IDs to limit search. Example: '#support,#bugs' or 'C123,C456'."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(50),
			mcp.Description("Maximum number of messages to return. Default is 50."),
		),
	), conversationsHandler.ConversationsGetUserTimelineHandler)

	s.AddTool(mcp.NewTool("conversations_analyze_thread",
		mcp.WithDescription("Get comprehensive thread analysis including participants, timeline, and key indicators (resolutions, escalations)."),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithString("thread_ts",
			mcp.Required(),
			mcp.Description("Thread timestamp in format 1234567890.123456."),
		),
		mcp.WithBoolean("include_resolution_indicators",
			mcp.DefaultBool(true),
			mcp.Description("Look for resolution indicators like ✅, 'resolved', 'fixed' patterns. Default is true."),
		),
	), conversationsHandler.ConversationsAnalyzeThreadHandler)

	s.AddTool(mcp.NewTool("conversations_search_by_reaction",
		mcp.WithDescription("Find messages with specific reactions (e.g., ✅ for resolved issues, ⚠️ for urgent)."),
		mcp.WithString("reaction_name",
			mcp.Required(),
			mcp.Description("Reaction emoji name. Example: 'white_check_mark', 'warning', 'eyes'."),
		),
		mcp.WithString("channel_id",
			mcp.Description("Limit search to a specific channel by its ID or name. Example: 'C1234567890' or '#general'. If not provided, channel_id is required."),
		),
		mcp.WithString("filter_date_after",
			mcp.Description("Only search messages after this date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday', 'Today', '30d', '120d', or '1y'. Defaults to 30 days ago."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(20),
			mcp.Description("Maximum number of messages to return. Default is 20."),
		),
	), conversationsHandler.ConversationsSearchByReactionHandler)

	s.AddTool(mcp.NewTool("conversations_find_patterns",
		mcp.WithDescription("Search for similar messages/patterns across channels to identify recurring issues."),
		mcp.WithString("pattern",
			mcp.Required(),
			mcp.Description("Text pattern to search for. Example: 'error code 500' or 'connection timeout'."),
		),
		mcp.WithString("filter_in_channels",
			mcp.Description("Comma-separated channel names or IDs to limit search. Example: '#support,#bugs' or 'C123,C456'."),
		),
		mcp.WithString("filter_date_after",
			mcp.Description("Only search messages after this date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday', 'Today', '30d', '120d', or '1y'."),
		),
		mcp.WithBoolean("exact_match",
			mcp.DefaultBool(false),
			mcp.Description("Require exact text match vs. contains. Default is false (partial matching)."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(50),
			mcp.Description("Maximum number of messages to return. Default is 50."),
		),
	), conversationsHandler.ConversationsFindPatternsHandler)

	channelsHandler := handler.NewChannelsHandler(provider, logger)

	s.AddTool(mcp.NewTool("channels_list",
		mcp.WithDescription("Get list of channels"),
		mcp.WithString("channel_types",
			mcp.Required(),
			mcp.Description("Comma-separated channel types. Allowed values: 'mpim', 'im', 'public_channel', 'private_channel'. Example: 'public_channel,private_channel,im'"),
		),
		mcp.WithString("sort",
			mcp.Description("Type of sorting. Allowed values: 'popularity' - sort by number of members/participants in each channel."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(100),
			mcp.Description("The maximum number of items to return. Must be an integer between 1 and 1000 (maximum 999)."), // context fix for cursor: https://github.com/korotovsky/slack-mcp-server/issues/7
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
	), channelsHandler.ChannelsHandler)

	logger.Info("Authenticating with Slack API...",
		zap.String("context", "console"),
	)
	ar, err := provider.Slack().AuthTest()
	if err != nil {
		logger.Fatal("Failed to authenticate with Slack",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	logger.Info("Successfully authenticated with Slack",
		zap.String("context", "console"),
		zap.String("team", ar.Team),
		zap.String("user", ar.User),
		zap.String("enterprise", ar.EnterpriseID),
		zap.String("url", ar.URL),
	)

	ws, err := text.Workspace(ar.URL)
	if err != nil {
		logger.Fatal("Failed to parse workspace from URL",
			zap.String("context", "console"),
			zap.String("url", ar.URL),
			zap.Error(err),
		)
	}

	s.AddResource(mcp.NewResource(
		"slack://"+ws+"/channels",
		"Directory of Slack channels",
		mcp.WithResourceDescription("This resource provides a directory of Slack channels."),
		mcp.WithMIMEType("text/csv"),
	), channelsHandler.ChannelsResource)

	s.AddResource(mcp.NewResource(
		"slack://"+ws+"/users",
		"Directory of Slack users",
		mcp.WithResourceDescription("This resource provides a directory of Slack users."),
		mcp.WithMIMEType("text/csv"),
	), conversationsHandler.UsersResource)

	return &MCPServer{
		server: s,
		logger: logger,
	}
}

func (s *MCPServer) ServeSSE(addr string) *server.SSEServer {
	s.logger.Info("Creating SSE server",
		zap.String("context", "console"),
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
		zap.String("address", addr),
	)
	return server.NewSSEServer(s.server,
		server.WithBaseURL(fmt.Sprintf("http://%s", addr)),
		server.WithSSEContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			ctx = auth.AuthFromRequest(s.logger)(ctx, r)

			return ctx
		}),
	)
}

func (s *MCPServer) ServeHTTP(addr string) *server.StreamableHTTPServer {
	s.logger.Info("Creating HTTP server",
		zap.String("context", "console"),
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
		zap.String("address", addr),
	)
	return server.NewStreamableHTTPServer(s.server,
		server.WithEndpointPath("/mcp"),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			ctx = auth.AuthFromRequest(s.logger)(ctx, r)

			return ctx
		}),
	)
}

func (s *MCPServer) ServeStdio() error {
	s.logger.Info("Starting STDIO server",
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
	)
	err := server.ServeStdio(s.server)
	if err != nil {
		s.logger.Error("STDIO server error", zap.Error(err))
	}
	return err
}

func buildLoggerMiddleware(logger *zap.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			logger.Info("Request received",
				zap.String("tool", req.Params.Name),
				zap.Any("params", req.Params),
			)

			startTime := time.Now()

			res, err := next(ctx, req)

			duration := time.Since(startTime)

			logger.Info("Request finished",
				zap.String("tool", req.Params.Name),
				zap.Duration("duration", duration),
			)

			return res, err
		}
	}
}
