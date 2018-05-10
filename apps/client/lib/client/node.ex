defmodule Client.Node do
  @moduledoc """
  Mana's ethereum node. A GenServer that communicates with a peer node to
  retrieve block data. It generates the full tree beginning with the genesis
  block.
  """
  use GenServer

  require Logger
  alias ExWire.Packet
  alias ExWire.Adapter.TCP

  def start_link(_) do
    GenServer.start_link(__MODULE__, [])
  end

  def init(_) do
    remote_test_peer = System.get_env("REMOTE_TEST_PEER")
    {:ok, peer} = ExWire.Struct.Peer.from_uri(remote_test_peer)

    db = MerklePatriciaTree.Test.random_ets_db()
    tree = Blockchain.Blocktree.new_tree()
    chain = Blockchain.Test.ropsten_chain()

    client_pid = subscribe_to_peer(peer)

    state = %{
      db: db,
      tree: tree,
      chain: chain,
      peer: peer,
      number: 0,
      current_headers: [],
      client_pid: client_pid
    }

    {:ok, state}
  end

  def subscribe_to_peer(peer) do
    {:ok, client_pid} = TCP.start_link(:outbound, peer)

    TCP.subscribe(client_pid, {:server, self()})

    client_pid
  end

  def handle_info({:packet, packet = %Packet.Status{}, _peer}, state) do
    send_status_message(state.client_pid, packet)
    request_block_headers(state.client_pid, state)
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.BlockHeaders{headers: headers}, _peer}, state) do
    request_block_bodies(state.client_pid, headers)
    {:noreply, %{state | current_headers: headers}}
  end

  def handle_info({:packet, %Packet.BlockBodies{blocks: blocks}, _peer}, state) do
    tree = process_block_bodies(blocks, state)
    Process.sleep(5000)
    client_pid = subscribe_to_peer(state.peer)

    new_state = %{
      state
      | number: hd(state.current_headers).number + 1,
        tree: tree,
        client_pid: client_pid
    }

    {:noreply, new_state}
  end

  def handle_info({:packet, %Packet.Hello{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.Ping{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.GetBlockHeaders{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.Transactions{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.NewBlockHashes{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, %Packet.Disconnect{}, _peer}, state) do
    {:noreply, state}
  end

  def handle_info({:packet, packet, _peer}, state) do
    raise "Unexpectd packet received: #{inspect(packet)}"
    {:noreply, state}
  end

  def send_status_message(client_pid, packet) do
    TCP.send_packet(client_pid, %Packet.Status{
      protocol_version: ExWire.Config.protocol_version(),
      network_id: ExWire.Config.network_id(),
      total_difficulty: packet.total_difficulty,
      best_hash: packet.genesis_hash,
      genesis_hash: packet.genesis_hash
    })
  end

  def request_block_headers(client_pid, state) do
    Logger.warn("Requesting block headers for block ##{inspect(state.number)}")

    ExWire.Adapter.TCP.send_packet(client_pid, %ExWire.Packet.GetBlockHeaders{
      block_identifier: state.number,
      max_headers: 1,
      skip: 0,
      reverse: false
    })
  end

  def request_block_bodies(client_pid, headers) do
    ExWire.Adapter.TCP.send_packet(client_pid, %ExWire.Packet.GetBlockBodies{
      hashes: Enum.map(headers, &Block.Header.hash/1)
    })
  end

  def process_block_bodies(blocks, state) do
    Logger.warn("Successfully received block ##{inspect(state.number)} from peer.")

    state.current_headers
    |> ex_wire_blocks_to_blockchain_blocks(blocks)
    |> add_blocks_to_blocktree(state.tree, state.chain, state.db)
  end

  def ex_wire_blocks_to_blockchain_blocks(headers, blocks) do
    headers
    |> Enum.with_index()
    |> Enum.map(fn {header, index} ->
      %Blockchain.Block{
        header: header,
        transactions: Enum.fetch!(blocks, index).transactions,
        ommers: Enum.fetch!(blocks, index).ommers
      }
    end)
  end

  def add_blocks_to_blocktree(blocks, original_tree, chain, db) do
    Enum.reduce(blocks, original_tree, fn block, tree ->
      {:ok, new_tree} = Blockchain.Blocktree.verify_and_add_block(tree, chain, block, db)
      new_tree
    end)
  end
end
