defmodule Mix.Tasks.Sync do
  require Logger
  alias ExWire.Packet
  alias ExWire.Adapter.TCP
  @remote_test_peer System.get_env("REMOTE_TEST_PEER") ||
    ExWire.Config.chain().nodes |> List.last()

  def run(args) do
  end
end
