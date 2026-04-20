##! Long-lived connection monitoring (Firewalla-inspired)
##!
##! Logs periodic snapshots of connections that have been alive for more than
##! 2 minutes. Useful for detecting VPN tunnels, streaming sessions, C2
##! channels, and other persistent connections.
##!
##! Adapted from Firewalla's bro-long-connection/main.zeek

@load base/protocols/conn
@load base/utils/time

module Conn;

export {
  ## Hack to access internal set_conn function for updating conn info
  function set_conn_log_data_hack(c: connection)
  {
    Conn::set_conn(c, T);
  }
}

module LongConnection;

export {
  redef enum Log::ID += { LOG };
}

redef record connection += {
  long_conn_offset: count &default=0;
};

event zeek_init() &priority=5
{
  Log::create_stream(LOG, [$columns=Conn::Info, $path="conn_long"]);
}

function long_callback(c: connection, cnt: count): interval
{
  Conn::set_conn_log_data_hack(c);

  # Include L2 MAC addresses if available
  if ( c$orig?$l2_addr )
    c$conn$orig_l2_addr = c$orig$l2_addr;
  if ( c$resp?$l2_addr )
    c$conn$resp_l2_addr = c$resp$l2_addr;

  Log::write(LongConnection::LOG, c$conn);

  # Re-log every 1 minute for ongoing connections
  return 1min;
}

event new_connection(c: connection)
{
  # Start monitoring after 2 minutes, log every 1 minute thereafter
  ConnPolling::watch(c, long_callback, 1, 2min);
}
