defmodule Mix.Tasks.Sync do
  require Logger

  def run(args) do
    Logger.info("Starting mana node")
    Mix.Tasks.Run.run(args ++ ["--no-halt"])
  end
end
