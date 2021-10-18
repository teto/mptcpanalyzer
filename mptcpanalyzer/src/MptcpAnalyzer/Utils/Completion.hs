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
import Options.Applicative.Help (Doc)
import Options.Applicative.Help.Pretty (displayS)
import Options.Applicative.Help (renderPretty)
import Data.Maybe (fromMaybe, listToMaybe)
import Options.Applicative.Common
import Options.Applicative.Internal
import Options.Applicative.Help.Chunk
-- import Options.Applicative.Help (parserHelp)

defaultCompleteFunc :: CompletionFunc IO
defaultCompleteFunc = completeFilename

-- runCompletion
--
-- bashCompletionQuery :: ParserInfo a -> ParserPrefs -> Richness -> [String] -> Int -> String -> IO [String]
-- bashCompletionQuery pinfo pprefs richness ws i _ = case runCompletion compl pprefs of

-- | Provide basic or rich command completions
data Richness
  = Standard
  -- ^ Add no help descriptions to the completions
  | Enriched Int Int
  -- ^ Include tab separated description for options
  --   and commands when available.
  --   Takes option description length and command
  --   description length.
  deriving (Eq, Ord, Show)


haskelineCompletionQuery :: ParserInfo a -> ParserPrefs -> Richness -> [String] -> Int -> String -> IO [String]
haskelineCompletionQuery pinfo pprefs richness ws i _ = case runCompletion compl pprefs of
  Just (Left (SomeParser p, a))
    -> list_options a p
  Just (Right c)
    -> run_completer c
  Nothing
    -> return []
  where
    compl = runParserInfo pinfo (drop 1 ws')

    list_options a
      = fmap concat
      . sequence
      . mapParser (opt_completions a)

    --
    -- Prior to 0.14 there was a subtle bug which would
    -- mean that completions from positional arguments
    -- further into the parse would be shown.
    --
    -- We therefore now check to see that
    -- hinfoUnreachableArgs is off before running the
    -- completion for position arguments.
    --
    -- For options and flags, ensure that the user
    -- hasn't disabled them with `--`.
    opt_completions argPolicy reachability opt = case optMain opt of
      OptReader ns _ _
         | argPolicy /= AllPositionals -> return . add_opt_help opt $ show_names ns
         | otherwise -> return []
      FlagReader ns _
         | argPolicy /= AllPositionals -> return . add_opt_help opt $ show_names ns
         | otherwise -> return []
      ArgReader rdr
         | argumentIsUnreachable reachability
        -> return []
         | otherwise
        -> run_completer (crCompleter rdr)
      CmdReader _ ns p
         | argumentIsUnreachable reachability -> return []
         | otherwise -> return . add_cmd_help p $ filter_names ns

    -- When doing enriched completions, add any help specified
    -- to the completion variables (tab separated).
    add_opt_help :: Functor f => Option a -> f String -> f String
    add_opt_help opt = case richness of
      Standard ->
        id
      Enriched len _ ->
        fmap $ \o ->
          let h = unChunk $ optHelp opt
          in  maybe o (\h' -> o ++ "\t" ++ render_line len h') h

    -- When doing enriched completions, add the command description
    -- to the completion variables (tab separated).
    add_cmd_help :: Functor f => (String -> Maybe (ParserInfo a)) -> f String -> f String
    add_cmd_help p = case richness of
      Standard ->
        id
      Enriched _ len ->
        fmap $ \cmd ->
          let h = p cmd >>= unChunk . infoProgDesc
          in  maybe cmd (\h' -> cmd ++ "\t" ++ render_line len h') h

    show_names :: [OptName] -> [String]
    show_names = filter_names . map showOption

    -- We only want to show a single line in the completion results description.
    -- If there was a line break, it would come across as a different completion
    -- possibility.
    render_line :: Int -> Doc -> String
    render_line len doc = case lines (displayS (renderPretty 1 len doc) "") of
      [] -> ""
      [x] -> x
      x : _ -> x ++ "..."

    filter_names :: [String] -> [String]
    filter_names = filter is_completion

    run_completer :: Completer -> IO [String]
    run_completer c = runCompleter c (fromMaybe "" (listToMaybe ws''))

    (ws', ws'') = splitAt i ws

    is_completion :: String -> Bool
    is_completion =
      case ws'' of
        w:_ -> isPrefixOf w
        _ -> const True

-- type CompletionFunc m = (String, String) -> m (String, [Completion]
-- haskeline System.Console.Haskeline.Completion
-- Performs completions from the given line state. The first String argument is the
--  contents of the line to the left of the cursor, reversed. The second String 
-- argument is the contents of the line to the right of the cursor. The output
--  String is the unused portion of the left half of the line, reversed
generateHaskelineCompleterFromParserInfo :: ParserPrefs -> ParserInfo a -> CompletionFunc IO
generateHaskelineCompleterFromParserInfo parserPrefs pinfo = 
  \(rleft, right) -> 
  let
    args = words $ reverse rleft
    fullArgs = words $ reverse rleft ++ right
    parserResult = trace ("\nParsing args " ++ reverse rleft ++ "\n") execParserPure parserPrefs pinfo args
  in do
    -- case parserResult of
    --   -- TODO convert the optparse applicative completer into an haskeline one !!
    --   (CompletionInvoked compl) -> trace "completion invoked" completeFilename (rleft, right)
    --   (Failure failure) -> let
    --       (pifail, exitCode, msgWidth) = execFailure failure "toto"
    --     in
    --       trace "autocomplete failure" completeFilename (rleft, right)
    --   _ ->  trace "no completion" (noCompletion (rleft, right))

    candidates <- haskelineCompletionQuery pinfo parserPrefs Standard fullArgs (length args) ""
    -- now onto converting candidates
    pure (rleft, map (\x -> System.Console.Haskeline.Completion x x False) candidates)

-- generateHaskelineCompleterFromParserInfo = haskelineCompletionQuery
-- generateHaskelineCompleterFromParser pprefs (infoParser pinfo)

generateHaskelineCompleterFromParser :: ParserPrefs -> Parser a -> CompletionFunc IO
generateHaskelineCompleterFromParser parserPrefs (OptP opt) = generateHaskelineCompleterFromOption opt
generateHaskelineCompleterFromParser _ _ = error "undefined "

-- argument completeWith / complete
placeholderCompletion :: System.Console.Haskeline.Completion
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
