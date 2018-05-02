defmodule Mix.Tasks.Mana do
  use Mix.Task

  @data "lib/sample_ropsten_blocks.dat"

  def run(_) do
    chain_data = initialize_chain()

    @data
    |> get_blocks()
    |> process_blocks(chain_data)
    |> IO.inspect()
  end

  defp initialize_chain do
    db = MerklePatriciaTree.Test.random_ets_db()
    tree = Blockchain.Blocktree.new_tree()
    chain = Blockchain.Test.ropsten_chain()

    {db, tree, chain}
  end

  defp get_blocks(file_path, count \\ 11) do
    file_path
    |> File.read!()
    |> BitHelper.from_hex()
    |> ExRLP.decode()
    |> Stream.map(&ExRLP.decode/1)
    |> Stream.map(&Blockchain.Block.deserialize/1)
    |> Enum.take(count)
  end

  defp process_blocks(blocks, {db, tree, chain}) do
    Enum.reduce(blocks, tree, fn block, tree ->
      {:ok, new_tree} = Blockchain.Blocktree.verify_and_add_block(tree, chain, block, db)

      new_tree
    end)
  end
end
