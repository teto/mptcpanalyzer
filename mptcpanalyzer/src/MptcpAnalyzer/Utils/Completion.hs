{-|

-}
module MptcpAnalyzer.Utils.Completion
where

import Options.Applicative
import System.Console.Haskeline
import Options.Applicative.Types
import Data.List (isPrefixOf)
-- import Options.Applicative.Help (parserHelp)

-- type CompletionFunc m = (String, String) -> m (String, [Completion]
-- haskeline System.Console.Haskeline.Completion
-- Performs completions from the given line state. The first String argument is the
--  contents of the line to the left of the cursor, reversed. The second String 
-- argument is the contents of the line to the right of the cursor. The output
--  String is the unused portion of the left half of the line, reversed

placeholderCompletion :: Completion
placeholderCompletion = Completion "itworked" "display" False

constCompletionFunc :: CompletionFunc IO
constCompletionFunc (left, right) = pure ("worked", [placeholderCompletion])

generateHaskelineCompleterFromOption :: Option a -> CompletionFunc IO
generateHaskelineCompleterFromOption (Option main _properties) = generateHaskelineCompleterFromOptreader main

generateHaskelineCompleterFromOptreader :: OptReader a -> CompletionFunc IO
-- generateHaskelineCompleterFromOptreader OptReader [OptName] (CReader a) (String -> ParseError)
-- CmdReader (Maybe String) [String] (String -> Maybe (ParserInfo a))

-- type CompletionFunc m = (String, String) -> m (String, [Completion])
completeInitialCommand :: CompletionFunc IO
completeInitialCommand = completeWord Nothing [' '] genCompletions
  where
    genCompletions :: String -> IO [Completion]
    genCompletions prefix = let filtered = filter (isPrefixOf prefix) commands in pure $ map (genCompletion prefix) filtered
    genCompletion prefix entry =  Completion entry "toto" True
    commands :: [String]
    commands = [
      "help"
      , "quit"
      , "load-csv"
      , "load-pcap"
      , "tcp-summary"
      , "mptcp-summary"
      , "list-tcp"
      , "map-tcp"
      , "map-mptcp"
      , "list-reinjections"
      , "list-mptcp"
      ]

-- p
generateHaskelineCompleterFromOptreader (CmdReader mbStr arrStr func) = \(left, right) -> pure (
  "replaced", if left == "pl" then [ Completion (show mbStr) "displayed msg" False ]
  else [])
generateHaskelineCompleterFromOptreader _ = error "undefined generateHaskelineCompleterFromOptreader"



-- ^ option reader
-- | FlagReader [OptName] !a
-- -- ^ flag reader
-- | ArgReader (CReader a)
-- -- ^ argument reader
-- | CmdReader (Maybe String) [String] (String -> Maybe (ParserInfo a))
-- -- ^ command reader
