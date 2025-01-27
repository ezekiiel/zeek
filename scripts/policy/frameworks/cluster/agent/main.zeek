##! This is the main "runtime" of a cluster agent. Zeek does not load this
##! directly; rather, the agent's bootstrapping module (in ./boot.zeek)
##! specifies it as the script to run in the node newly created via Zeek's
##! supervisor.

@load base/frameworks/broker

@load policy/frameworks/cluster/controller/config
@load policy/frameworks/cluster/controller/log
@load policy/frameworks/cluster/controller/request

@load ./api

module ClusterAgent::Runtime;

redef ClusterController::role = ClusterController::Types::AGENT;

# The global configuration as passed to us by the controller
global g_config: ClusterController::Types::Configuration;

# A map to make other instance info accessible
global g_instances: table[string] of ClusterController::Types::Instance;

# A map for the nodes we run on this instance, via this agent.
global g_nodes: table[string] of ClusterController::Types::Node;

# The node map employed by the supervisor to describe the cluster
# topology to newly forked nodes. We refresh it when we receive
# new configurations.
global g_data_cluster: table[string] of Supervisor::ClusterEndpoint;


event SupervisorControl::create_response(reqid: string, result: string)
	{
	local req = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( |result| > 0 )
		{
		local msg = fmt("failed to create node %s: %s", name, result);
		ClusterController::Log::error(msg);
		event ClusterAgent::API::notify_error(ClusterAgent::name, msg, name);
		}

	ClusterController::Request::finish(reqid);
	}

event SupervisorControl::destroy_response(reqid: string, result: bool)
	{
	local req = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( ! result )
		{
		local msg = fmt("failed to destroy node %s, %s", name, reqid);
		ClusterController::Log::error(msg);
		event ClusterAgent::API::notify_error(ClusterAgent::name, msg, name);
		}

	ClusterController::Request::finish(reqid);
	}

function supervisor_create(nc: Supervisor::NodeConfig)
	{
	local req = ClusterController::Request::create();
	req$supervisor_state = ClusterController::Request::SupervisorState($node = nc$name);
	event SupervisorControl::create_request(req$id, nc);
	ClusterController::Log::info(fmt("issued supervisor create for %s, %s", nc$name, req$id));
	}

function supervisor_destroy(node: string)
	{
	local req = ClusterController::Request::create();
	req$supervisor_state = ClusterController::Request::SupervisorState($node = node);
	event SupervisorControl::destroy_request(req$id, node);
	ClusterController::Log::info(fmt("issued supervisor destroy for %s, %s", node, req$id));
	}

event ClusterAgent::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::set_configuration_request %s", reqid));

	local nodename: string;
	local node: ClusterController::Types::Node;
	local nc: Supervisor::NodeConfig;
	local msg: string;

	# Adopt the global configuration provided.
	# XXX this can later handle validation and persistence
	# XXX should do this transactionally, only set when all else worked
	g_config = config;

	# Refresh the instances table:
	g_instances = table();
	for ( inst in config$instances )
		g_instances[inst$name] = inst;

	# Terminate existing nodes
	for ( nodename in g_nodes )
		supervisor_destroy(nodename);

	g_nodes = table();

	# Refresh the data cluster and nodes tables

	g_data_cluster = table();
	for ( node in config$nodes )
		{
		if ( node$instance == ClusterAgent::name )
			g_nodes[node$name] = node;

		local cep = Supervisor::ClusterEndpoint(
		    $role = node$role,
		    $host = g_instances[node$instance]$host,
		    $p = node$p);

		if ( node?$interface )
			cep$interface = node$interface;

		g_data_cluster[node$name] = cep;
		}

	# Apply the new configuration via the supervisor

	for ( nodename in g_nodes )
		{
		node = g_nodes[nodename];
		nc = Supervisor::NodeConfig($name=nodename);

		if ( ClusterAgent::cluster_directory != "" )
			nc$directory = ClusterAgent::cluster_directory;

		if ( node?$interface )
			nc$interface = node$interface;
		if ( node?$cpu_affinity )
			nc$cpu_affinity = node$cpu_affinity;
		if ( node?$scripts )
			nc$scripts = node$scripts;
		if ( node?$env )
			nc$env = node$env;

		# XXX could use options to enable per-node overrides for
		# directory, stdout, stderr, others?

		nc$cluster = g_data_cluster;
		supervisor_create(nc);
		}

	# XXX this currently doesn not fail if any of above problems occurred,
	# mainly due to the tediousness of handling the supervisor's response
	# events asynchonously. The only indication of error will be
	# notification events to the controller.

	if ( reqid != "" )
		{
		local res = ClusterController::Types::Result(
		    $reqid = reqid,
		    $instance = ClusterAgent::name);

		ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_response %s",
		                                 ClusterController::Types::result_to_string(res)));
		event ClusterAgent::API::set_configuration_response(reqid, res);
		}
	}

event ClusterAgent::API::agent_welcome_request(reqid: string)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::agent_welcome_request %s", reqid));

	local res = ClusterController::Types::Result(
	    $reqid = reqid,
	    $instance = ClusterAgent::name);

	ClusterController::Log::info(fmt("tx ClusterAgent::API::agent_welcome_response %s",
	                                 ClusterController::Types::result_to_string(res)));
	event ClusterAgent::API::agent_welcome_response(reqid, res);
	}

event ClusterAgent::API::agent_standby_request(reqid: string)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::agent_standby_request %s", reqid));

	# We shut down any existing cluster nodes via an empty configuration,
	# and fall silent. We do not unpeer/disconnect (assuming we earlier
	# peered/connected -- otherwise there's nothing we can do here via
	# Broker anyway), mainly to keep open the possibility of running
	# cluster nodes again later.
	event ClusterAgent::API::set_configuration_request("", ClusterController::Types::Configuration());

	local res = ClusterController::Types::Result(
	    $reqid = reqid,
	    $instance = ClusterAgent::name);

	ClusterController::Log::info(fmt("tx ClusterAgent::API::agent_standby_response %s",
	                                 ClusterController::Types::result_to_string(res)));
	event ClusterAgent::API::agent_standby_response(reqid, res);
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	# This does not (cannot?) immediately verify that the new peer
	# is in fact a controller, so we might send this in vain.
	# Controllers register the agent upon receipt of the event.

	local epi = ClusterAgent::endpoint_info();

	event ClusterAgent::API::notify_agent_hello(epi$id,
	    to_addr(epi$network$address), ClusterAgent::API::version);
	}

event zeek_init()
	{
	local epi = ClusterAgent::endpoint_info();
	local agent_topic = ClusterAgent::topic_prefix + "/" + epi$id;

	# The agent needs to peer with the supervisor -- this doesn't currently
	# happen automatically. The address defaults to Broker's default, which
	# relies on ZEEK_DEFAULT_LISTEN_ADDR and so might just be "". Broker
	# internally falls back to listening on any; we pick 127.0.0.1.
	local supervisor_addr = Broker::default_listen_address;
	if ( supervisor_addr == "" )
		supervisor_addr = "127.0.0.1";

	Broker::peer(supervisor_addr, Broker::default_port, Broker::default_listen_retry);

	# Agents need receive communication targeted at it, and any responses
	# from the supervisor.
	Broker::subscribe(agent_topic);
	Broker::subscribe(SupervisorControl::topic_prefix);

	# Auto-publish a bunch of events. Glob patterns or module-level
	# auto-publish would be helpful here.
	Broker::auto_publish(agent_topic, ClusterAgent::API::set_configuration_response);
	Broker::auto_publish(agent_topic, ClusterAgent::API::agent_welcome_response);
	Broker::auto_publish(agent_topic, ClusterAgent::API::agent_standby_response);

	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_agent_hello);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_change);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_error);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_log);

	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::create_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::create_response);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::destroy_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::destroy_response);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::restart_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::restart_response);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::stop_request);

	# Establish connectivity with the controller.
	if ( ClusterAgent::controller$address != "0.0.0.0" )
		{
		# We connect to the controller.
		Broker::peer(ClusterAgent::controller$address,
		             ClusterAgent::controller$bound_port,
		             ClusterController::connect_retry);
		}
	else
		{
		# Controller connects to us; listen for it.
		Broker::listen(cat(epi$network$address), epi$network$bound_port);
		}

	ClusterController::Log::info("agent is live");
	}
