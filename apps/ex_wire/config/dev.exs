use Mix.Config

config :ex_wire,
  network_adapter: {ExWire.Adapter.UDP, NetworkClient},
  sync: true,
  private_key:
    <<10, 122, 189, 137, 166, 190, 127, 238, 229, 16, 211, 182, 104, 78, 138, 37, 146, 116, 90,
      68, 76, 86, 168, 24, 200, 155, 0, 99, 58, 226, 211, 30>>,
  discovery: true,
  node_discovery: [
    network_adapter: {ExWire.Adapter.UDP, NetworkClient},
    kademlia_process_name: KademliaState,
    supervisor_name: ExWire.NodeDiscoverySupervisor,
    port: 30_304
  ]
