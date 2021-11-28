let Replica = https://raw.githubusercontent.com/ReplicaTest/replica-dhall/main/package.dhall
let Prelude = Replica.Prelude


-- let extra_args = "--log-level Info"

let quoteArg : Text -> Text = \(t: Text) -> "'" ++ t ++ "'"
let wrapCmd : List Text -> Text = \(args: List Text) -> "mptcpanalyzer " ++ (Prelude.Text.concatSep " " (Prelude.List.map Text Text quoteArg (args # [ "quit" ])))
in {
  wrapCmd
}
