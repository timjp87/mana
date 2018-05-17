defmodule EVM.Builtin do
  @moduledoc """
  Implements the built-in functions as defined in Appendix E
  of the Yellow Paper. These are contract functions that
  natively exist in Ethereum.

  TODO: Implement and add doc tests.
  """

  @spec run_ecrec(EVM.Gas.t(), EVM.ExecEnv.t()) ::
          {EVM.Gas.t(), EVM.SubState.t(), EVM.ExecEnv.t(), EVM.VM.output()}
  def run_ecrec(gas, exec_env), do: {gas, %EVM.SubState{}, exec_env, <<>>}

  @doc """
  Runs SHA256 hashing

  Checks if there is enough gas for the operation.
  Calculates the remaining gas after the SHA256 is executed.
  Executes SHA256 hashing.

  ## Examples

      iex> EVM.Builtin.run_sha256(3000,  %EVM.ExecEnv{data: <<1, 2, 3>>})
      {2928, %EVM.SubState{}, %EVM.ExecEnv{data: <<1, 2, 3>>}, <<241, 136, 94, 218, 84, 183, 160, 83, 49, 140, 212, 30, 32, 147,
              34, 13, 171, 21, 214, 83, 129, 177, 21, 122, 54, 51, 168, 59, 253,
              92, 146, 57>>}
  """
  @spec run_sha256(EVM.Gas.t(), EVM.ExecEnv.t()) ::
          {EVM.Gas.t(), EVM.SubState.t(), EVM.ExecEnv.t(), EVM.VM.output()}
  def run_sha256(gas, exec_env) do
    input = exec_env.data
    used_gas = 60 + 12 * MathHelper.bits_to_words(byte_size(input))

    if(used_gas < gas) do
      remaining_gas = gas - used_gas
      result = ExthCrypto.Hash.hash(input, ExthCrypto.Hash.kec())
      {remaining_gas, %EVM.SubState{}, exec_env, result}
    else
      {gas, %EVM.SubState{}, exec_env, <<>>}
    end
  end

  @spec run_rip160(EVM.Gas.t(), EVM.ExecEnv.t()) ::
          {EVM.Gas.t(), EVM.SubState.t(), EVM.ExecEnv.t(), EVM.VM.output()}
  def run_rip160(gas, exec_env), do: {gas, %EVM.SubState{}, exec_env, <<>>}

  @spec run_id(EVM.Gas.t(), EVM.ExecEnv.t()) ::
          {EVM.Gas.t(), EVM.SubState.t(), EVM.ExecEnv.t(), EVM.VM.output()}
  def run_id(gas, exec_env), do: {gas, %EVM.SubState{}, exec_env, <<>>}
end
