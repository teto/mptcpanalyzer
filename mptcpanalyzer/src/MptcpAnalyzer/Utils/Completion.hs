{-|
Module: MptcpAnalyzer.Utils.Completion
Maintainer  : matt
License     : GPL-3


  missingArgP :: ParseError -> Completer -> m a
  errorP :: ParseError -> m a

parseError peut renvoyer un missingArgP qui du coup aura le completer, qu'on n'a plus qu'a transcrire dans un completer haskeline !

-}
module MptcpAnalyzer.Utils.Completion (
  -- completeInitialCommand
  generateHaskelineCompleterFromParser
  , generateHaskelineCompleterFromParserInfo
  -- , generateHaskelineCompleterFromOption
)
where

import Options.Applicative
import System.Console.Haskeline (CompletionFunc, completeFilename, noCompletion, Completion(..))
import System.Console.Haskeline.Completion (listFiles)
import Options.Applicative.Types
import Data.List (isPrefixOf)
import Debug.Trace
-- import Options.Applicative.Help (parserHelp)

defaultCompleteFunc :: CompletionFunc IO
defaultCompleteFunc = completeFilename

-- type CompletionFunc m = (String, String) -> m (String, [Completion]
-- haskeline System.Console.Haskeline.Completion
-- Performs completions from the given line state. The first String argument is the
--  contents of the line to the left of the cursor, reversed. The second String 
-- argument is the contents of the line to the right of the cursor. The output
--  String is the unused portion of the left half of the line, reversed
generateHaskelineCompleterFromParserInfo :: ParserPrefs -> ParserInfo a -> CompletionFunc IO
generateHaskelineCompleterFromParserInfo parserPrefs pinfo = 
  -- for now assume we have no characters in right
  -- runCompletion
  \(rleft, right) -> 
  let
    args = words $ reverse rleft
    parserResult = execParserPure parserPrefs pinfo args
  in
    case parserResult of

      -- TODO convert the optparse applicative completer into an haskeline one !!
      (CompletionInvoked compl) -> completeFilename (rleft, right)
      -- trace "no completion"
      _ ->  noCompletion (rleft, right)

  -- generateHaskelineCompleterFromParser pprefs (infoParser pinfo)

generateHaskelineCompleterFromParser :: ParserPrefs -> Parser a -> CompletionFunc IO
generateHaskelineCompleterFromParser parserPrefs (OptP opt) = generateHaskelineCompleterFromOption opt
generateHaskelineCompleterFromParser _ _ = error "undefined "

-- argument completeWith / complete
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
-- completeInitialCommand :: CompletionFunc IO
-- completeInitialCommand = completeWord Nothing [' '] genCompletions

-- se baser sur completeFilename aussi
-- TODO call the parser on it and check where it fails
generateHaskelineCompleterFromOptreader (CmdReader mbGrpCommand arrStr func) =
  \(rleft, right) -> let
    filtered = filter (isPrefixOf prefix) arrStr
    -- genCompletions :: String -> IO [Completion]
    -- genCompletions prefix = map (genCompletion prefix)
    -- "TODO show help for " ++
    genCompletion entry =  Completion entry ( entry) True
    prefix = reverse rleft
    longestCommonPrefix entries = rleft
    completions = map (genCompletion) filtered
  in
    -- TODO call execParserPure ParserInfo a 
    
    trace "completion called" (pure (
    -- return longest common prefixes
    "", completions
    ))

-- generateHaskelineCompleterFromOptreader (FlagReader ns x) = FlagReader ns (f x)
-- ArgReader can have custom completer
-- newtype Completer = Completer
--   { runCompleter :: String -> IO [String] }

-- TODO convert the C
-- generateHaskelineCompleterFromOptreader (ArgReader (CReader completer _)) = 
generateHaskelineCompleterFromOptreader _ = error "undefined generateHaskelineCompleterFromOptreader"



-- ^ option reader
-- | FlagReader [OptName] !a
-- -- ^ flag reader
-- | ArgReader (CReader a)
-- -- ^ argument reader
-- | CmdReader (Maybe String) [String] (String -> Maybe (ParserInfo a))
-- -- ^ command reader
