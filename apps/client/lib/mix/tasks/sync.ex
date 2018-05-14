defmodule Mix.Tasks.Sync do
  require Logger

  def run(args) do
    Logger.info("Starting mana node")

    Mix.Tasks.Run.run(run_args() ++ args)
  end

  def run_args do
    if iex_running?() do
      []
    else
      ["--no-halt"]
    end
  end

  defp iex_running? do
    Code.ensure_loaded?(IEx) and IEx.started?()
  end
end
