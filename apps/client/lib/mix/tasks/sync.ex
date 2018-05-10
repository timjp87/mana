defmodule Mix.Tasks.Sync do
  require Logger
  alias ExWire.Packet
  alias ExWire.Adapter.TCP

  @db MerklePatriciaTree.Test.random_ets_db()
  @initial_tree Blockchain.Blocktree.new_tree()
  @chain Blockchain.Test.ropsten_chain()
  @remote_test_peer System.get_env("REMOTE_TEST_PEER") ||
                      ExWire.Config.chain().nodes |> List.last()

  def run(args) do
    {:ok, peer} = ExWire.Struct.Peer.from_uri(@remote_test_peer)

    db = MerklePatriciaTree.Test.random_ets_db()
    tree = Blockchain.Blocktree.new_tree()
    chain = Blockchain.Test.ropsten_chain()

    state = %{
      db: db,
      tree: tree,
      chain: chain,
      peer: peer,
      number: 0,
      current_headers: []
    }

    sync_block(state)
  end

  def sync_block(state) do
    {:ok, client_pid} = TCP.start_link(:outbound, state.peer)

    TCP.subscribe(client_pid, {:server, self()})

    handle_packet(client_pid, state)
  end

  def handle_packet(client_pid, state) do
    receive do
      {:packet, packet = %Packet.Status{}, _peer} ->
        send_status_message(client_pid, packet)
        request_block_headers(client_pid, state)
        handle_packet(client_pid, state)

      {:packet, %Packet.BlockHeaders{headers: headers}, _peer} ->
        request_block_bodies(client_pid, headers)
        handle_packet(client_pid, %{state | current_headers: headers})

      {:packet, %Packet.BlockBodies{blocks: blocks}, _peer} ->
        tree = process_block_bodies(blocks, state)
        Process.sleep(5000)
        sync_block(%{state | number: hd(state.current_headers).number + 1, tree: tree})

      {:packet, _packet, _peer} ->
        handle_packet(client_pid, state)

      error ->
        raise "Unexpected packet, got: #{inspect(error)}"
    end
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
