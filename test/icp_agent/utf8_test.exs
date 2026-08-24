defmodule ICPAgent.UTF8Test do
  use ExUnit.Case, async: true

  describe "utf8_to_list/1 with maps" do
    test "recursively processes every value in a plain map" do
      assert ICPAgent.utf8_to_list(%{"a" => "b"}) == %{"a" => "b"}
      assert ICPAgent.utf8_to_list(%{"a" => 1}) == %{"a" => 1}
    end

    test "recurses through nested maps" do
      input = %{"outer" => %{"inner" => "value"}}
      assert ICPAgent.utf8_to_list(input) == input
    end

    test "does not match structs (so they pass through unchanged)" do
      struct = %URI{scheme: "https", host: "example.com"}
      assert ICPAgent.utf8_to_list(struct) == struct
    end

    test "preserves map key types" do
      assert ICPAgent.utf8_to_list(%{1 => "a"}) == %{1 => "a"}
      assert ICPAgent.utf8_to_list(%{:atom => "a"}) == %{atom: "a"}
    end
  end

  describe "utf8_to_list/1 with lists" do
    test "recurses through every element of a list" do
      assert ICPAgent.utf8_to_list(["a", "b", "c"]) == ["a", "b", "c"]
    end

    test "recurses through nested lists" do
      assert ICPAgent.utf8_to_list([["a", "b"], ["c"]]) == [["a", "b"], ["c"]]
    end

    test "handles an empty list" do
      assert ICPAgent.utf8_to_list([]) == []
    end

    test "recurses through maps inside lists" do
      assert ICPAgent.utf8_to_list([%{"k" => "v"}]) == [%{"k" => "v"}]
    end
  end

  describe "utf8_to_list/1 with utf8 tagged tuples" do
    test "unwraps {:utf8, binary} to the binary value" do
      assert ICPAgent.utf8_to_list({:utf8, "hello"}) == "hello"
    end

    test "does not unwrap other 2-tuples" do
      assert ICPAgent.utf8_to_list({:other, "hello"}) == {:other, "hello"}
      assert ICPAgent.utf8_to_list({"x", "y"}) == {"x", "y"}
    end

    test "does not match {:utf8, non_binary}" do
      assert ICPAgent.utf8_to_list({:utf8, 123}) == {:utf8, 123}
      assert ICPAgent.utf8_to_list({:utf8, nil}) == {:utf8, nil}
    end
  end

  describe "utf8_to_list/1 with other values" do
    test "passes binaries through unchanged" do
      assert ICPAgent.utf8_to_list("hello") == "hello"
      assert ICPAgent.utf8_to_list("") == ""
    end

    test "passes integers through unchanged" do
      assert ICPAgent.utf8_to_list(42) == 42
    end

    test "passes atoms through unchanged" do
      assert ICPAgent.utf8_to_list(:atom) == :atom
      assert ICPAgent.utf8_to_list(nil) == nil
    end

    test "passes structs through unchanged" do
      now = ~U[2024-01-01 00:00:00Z]
      assert ICPAgent.utf8_to_list(now) == now
    end

    test "passes CBOR tags through unchanged" do
      tag = %CBOR.Tag{tag: :bytes, value: "data"}
      assert ICPAgent.utf8_to_list(tag) == tag
    end
  end

  describe "utf8_to_list/1 combined behavior" do
    test "recurses through maps containing utf8-tagged tuples" do
      input = %{"key" => {:utf8, "value"}, "other" => "plain"}
      assert ICPAgent.utf8_to_list(input) == %{"key" => "value", "other" => "plain"}
    end

    test "recurses through lists containing utf8-tagged tuples" do
      assert ICPAgent.utf8_to_list([{:utf8, "x"}, "y"]) == ["x", "y"]
    end
  end
end
