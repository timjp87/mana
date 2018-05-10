defmodule Mix.Tasks.Sync do
  alias MerklePatriciaTree.Trie
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

    sync_block(0, db, tree, chain, peer)
  end

  def sync_block(number, db, tree, chain, peer) do
    {:ok, client_pid} = TCP.start_link(:outbound, peer)

    TCP.subscribe(client_pid, {__MODULE__, :receive_packet, [self()]})

    receive_status(client_pid, db, tree, chain, number)
  end

  def receive_status(client_pid, db, tree, chain, number) do
    IO.inspect("Requesting block ##{number}")

    receive do
      {:incoming_packet,
       _packet = %Packet.Status{
         best_hash: best_hash,
         total_difficulty: total_difficulty,
         genesis_hash: genesis_hash
       }} ->
        # Send a simple status message
        TCP.send_packet(client_pid, %Packet.Status{
          protocol_version: ExWire.Config.protocol_version(),
          network_id: ExWire.Config.network_id(),
          total_difficulty: total_difficulty,
          best_hash: genesis_hash,
          genesis_hash: genesis_hash
        })

        ExWire.Adapter.TCP.send_packet(client_pid, %ExWire.Packet.GetBlockHeaders{
          block_identifier: number,
          max_headers: 1,
          skip: 0,
          reverse: false
        })

        receive_block_headers(client_pid, db, tree, chain)

      {:incoming_packet, packet} ->
        if System.get_env("TRACE"),
          do: Logger.debug("Expecting status packet, got: #{inspect(packet)}")

        receive_status(client_pid, db, tree, chain, number)
        # after
        #   15_000 ->
        #     raise "Expected status, but did not receive before timeout."
    end
  end

  def receive_block_headers(client_pid, db, tree, chain) do
    receive do
      {:incoming_packet, packet = %Packet.BlockHeaders{headers: headers}} ->
        ExWire.Adapter.TCP.send_packet(client_pid, %ExWire.Packet.GetBlockBodies{
          hashes: Enum.map(headers, &Block.Header.hash/1)
        })

        receive_block_bodies(client_pid, headers, db, tree, chain)

      {:incoming_packet, packet} ->
        if System.get_env("TRACE"),
          do: Logger.debug("Expecting block headers packet, got: #{inspect(packet)}")

        receive_block_headers(client_pid, db, tree, chain)

      error ->
        IO.inspect(error)
        # after
        #   30_000 ->
        #     raise "Expected block headers, but did not receive before timeout."
    end
  end

  def receive_block_bodies(client_pid, headers, db, tree, chain) do
    receive do
      {:incoming_packet, packet = %Packet.BlockBodies{blocks: blocks}} ->
        tree =
          Enum.with_index(headers)
          |> Enum.map(fn {header, index} ->
            %Blockchain.Block{
              header: header,
              transactions: Enum.fetch!(blocks, index).transactions,
              ommers: Enum.fetch!(blocks, index).ommers
            }
          end)
          |> Enum.reduce(tree, fn block, new_tree ->
            add_block_to_blocktree(block, new_tree, chain, db)
          end)

        Process.sleep(10000)
        {:ok, peer} = ExWire.Struct.Peer.from_uri(@remote_test_peer)
        sync_block(hd(headers).number + 1, db, tree, chain, peer)

        Logger.warn("Successfully received genesis block from peer.")

      {:incoming_packet, packet} ->
        # if System.get_env("TRACE"),
        #   do: Logger.debug("Expecting block bodies packet, got: #{inspect(packet)}")

        receive_block_bodies(client_pid, headers, db, tree, chain)
        # after
        #   15_000 ->
        #     raise "Expected block bodies, but did not receive before timeout."
    end
  end

  def add_block_to_blocktree(block, tree, chain, db) do
    {:ok, new_tree} = Blockchain.Blocktree.verify_and_add_block(tree, chain, block, db)

    new_tree
  end

  def receive(inbound_message, pid) do
    send(pid, {:inbound_message, inbound_message})
  end

  def receive_packet(inbound_packet, pid) do
    send(pid, {:incoming_packet, inbound_packet})
  end
end
