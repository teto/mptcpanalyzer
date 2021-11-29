{-# LANGUAGE CPP #-}
{-|
Module: MptcpAnalyzer.Utils.Completion
Maintainer  : matt
License     : GPL-3


  missingArgP :: ParseError -> Completer -> m a
  errorP :: ParseError -> m a

parseError peut renvoyer un missingArgP qui du coup aura le completer, qu'on n'a plus qu'a transcrire dans un completer haskeline !

-}
module MptcpAnalyzer.Utils.Completion (
  generateHaskelineCompleterFromParserInfo
  , completePath
  , readFilename
)
where

import Data.Char (isSpace)
import Data.List (isPrefixOf, isSuffixOf, stripPrefix)
import Data.Maybe (fromJust, fromMaybe, listToMaybe)
import Debug.Trace
import Options.Applicative
import Options.Applicative.Common
import Options.Applicative.Help (Doc, renderPretty)
import Options.Applicative.Help.Chunk
import Options.Applicative.Help.Pretty (displayS)
import Options.Applicative.Internal hiding (Completion)
import Options.Applicative.Types hiding (replacement)
import System.Console.Haskeline
       (Completion(..), CompletionFunc, completeFilename, noCompletion)
import System.Console.Haskeline.Completion (listFiles)
-- import Options.Applicative.Help (parserHelp)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix (fileExist, getFileStatus, isRegularFile)

defaultCompleteFunc :: CompletionFunc IO
defaultCompleteFunc = completeFilename


-- | We use unsafePerformIO to work around optparse-applicative limitation
readFilename :: String -> Either String FilePath
readFilename path =
  -- fileExist seems to consider files and folders alike
  let exists = unsafePerformIO $ do
        t <- fileExist path
        if t then
          getFileStatus path >>= return . isRegularFile
        else
          return False
  in
  case exists of
    True ->
#ifdef DEBUG_COMPLETION
  trace "right path"
#endif
      Right path
    False -> 
#ifdef DEBUG_COMPLETION
      trace ("path " ++ path ++ " DOES NOT EXIST (returning Left)")
#endif
      Left "Path does not exist"

-- optparse2haskelineCompletion
oa2hl :: CompletionItem -> Completion
oa2hl (CompletionItem replacement' display' isFinished') =
  Completion replacement' display' isFinished'

hl2oa :: Completion -> CompletionItem
hl2oa (Completion replacement' display' isFinished') =
  CompletionItem replacement' display' isFinished'

-- newtype Completer = Completer
--   { runCompleter :: String -> IO [String] }
-- type CompletionFunc m = (String, String) -> m (String, [Completion])
-- "optparse-applicative" wrapper around haskelinec>s 'completeFilename'
-- The first 'String' argument is the contents of the line to the left of the cursor,
-- reversed.
-- The second 'String' argument is the contents of the line to the right of the cursor.
completePath :: Completer
completePath = mkCompleter $ \entry -> do
  -- case words entry of
  --   [] -> ""
  --   x -> tail
  (_, completions) <- 
#ifdef DEBUG_COMPLETION
    trace "completeFilename called with entry"
#endif 
    completeFilename (reverse entry, "")
  let completions' = map hl2oa completions
  putStrLn $ "completePath called !! with entry: [" ++ entry ++ "]"
  return $
#ifdef DEBUG_COMPLETION
    trace ("completions: " ++ show completions)
#endif
    completions'

-- drop 1 was for progname ?
-- TODO make it so that it returns [Completion] instead
-- runParser and runParserStep
haskelineCompletionQuery :: ParserInfo a -> ParserPrefs
  -> [String]
  -- ^ words , Should be Args ?
  -- -> Int
  -- ^ current word (to remove ?)
  -> String -> IO [Completion]
haskelineCompletionQuery pinfo pprefs ws rest = case runCompletion compl pprefs of
  Just (Left (SomeParser p, a)) ->
#ifdef DEBUG_COMPLETION
    trace "listing options\n"
#endif
    list_options a p
  -- terminal case
  Just (Right c) ->
#ifdef DEBUG_COMPLETION
    trace "terminal completer\n"
#endif
    run_completer c
  Nothing -> 
#ifdef DEBUG_COMPLETION
  trace "runCompletion into Nothing\n"
#endif
    return []
  where
    --current word
    -- runParserInfo te renvoie une (Completion a)
    -- drop 1 looks necesary here ?
    compl = 
#ifdef DEBUG_COMPLETION
      traceShow ("Passing args " ++ show ws ++ "\n")
#endif
      runParserInfo pinfo ws
    -- runParserInfo calls runParserFully
    -- compl = runParserInfo pinfo ws
    -- trace ("runCompleter: ws=" ++ show ws ++ " i=" ++ show i ++ "ws''= " ++ show ws'' ++ " rest=" ++ show rest)

    list_options a
      = fmap concat
      . sequence
      . mapParser (opt_completions a)

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
    -- opt_completions :: ArgPolicy -> ArgumentReachability -> Option a -> m [Completion]
    -- trace ("argPolicy " ++ show argPolicy ++ "\n")
    opt_completions argPolicy reachability opt = case  optMain opt of
      OptReader ns _ _
         | argPolicy /= AllPositionals -> trace "unreachable OptReader\n" return . add_opt_help opt $ show_names ns
         -- trace "optreader\n"
         | otherwise ->  return []
      FlagReader ns _
         | argPolicy /= AllPositionals -> trace "unreachableflag reader\n" return . add_opt_help opt $ show_names ns
         -- trace "flagreader\n"
         | otherwise ->  return []
      ArgReader rdr
         | argumentIsUnreachable reachability -> trace "unreachable\n " return []
         -- TODO restore arg Reader with file autocomplete
         --  | otherwise -> return []
         -- trace "argreader\n"
         | otherwise -> run_completer (crCompleter rdr)
         -- >>= \x -> return $ Completion x "argreader help" True
      CmdReader _ ns p
         | argumentIsUnreachable reachability -> trace "unreachable cmdreader\n" return []
         -- trace "cmdreader\n"
         | otherwise -> return . add_cmd_help p $ filter_names ns

    -- When doing enriched completions, add any help specified
    -- to the completion variables (tab separated).
    add_opt_help :: Functor f => Option a -> f String -> f Completion
    add_opt_help opt = fmap $ \o ->
          let h = unChunk $ optHelp opt
              len = 80
          in  maybe (Completion o "option help" True) (\h' -> Completion o (o ++ "\t" ++ render_line len h' ) False) h

    -- When doing enriched completions, add the command description
    -- to the completion variables (tab separated).
    add_cmd_help :: Functor f => (String -> Maybe (ParserInfo a)) -> f String -> f Completion
    add_cmd_help p = fmap $ \cmd -> let
            len = 80
            h = p cmd >>= unChunk . infoProgDesc
          in
            -- if there is a parser info we add help
            maybe (Completion cmd "cmd help" True) (\h' -> Completion cmd (cmd ++ "\t" ++ render_line len h') False) h

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
    filter_names = filter (isPrefixOf currentArg)

    -- TODO fix the arg
    run_completer :: Completer -> IO [Completion]
    -- (fromMaybe "" (listToMaybe [currentArg]))
    run_completer c = trace ("running completer against " ++ currentArg) runCompleter c currentArg >>= return . map oa2hl

    currentArg :: String
    currentArg = case ws of
      [] -> ""
      ws' -> last ws'

-- The output String is the unused portion of the left half of the line, reversed.
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
    leftArgs = words $ reverse rleft
    fullArgs = reverse rleft ++ right
    fullArgs' = words fullArgs ++ if trailingSpace then [""] else []
    currentWord = last leftArgs
    parserResult = trace ("\nParsing args " ++ reverse rleft ++ "\n") execParserPure parserPrefs pinfo leftArgs
    trailingSpace = " " `isSuffixOf` fullArgs
    leftRes = case fullArgs' of
      [] -> ""
      _ -> mconcat (init fullArgs') ++ if trailingSpace then " " else ""
  in do
    candidates <- haskelineCompletionQuery pinfo parserPrefs (trace ("\n" ++ show fullArgs' ++ "\n" ) fullArgs') ""
    putStrLn $ "Returned candidates : " ++ show candidates
    -- now onto converting candidates
    -- TODO stripper le commonPrefix
    -- map (\x -> System.Console.Haskeline.Completion x x False)


    pure (" " ++ reverse leftRes,  map (
      id
      -- \x -> x { replacement = fromMaybe "error" (stripPrefix currentWord (display x)) }
      )
      candidates)


-- runParserInfo on a subparser only goes one level deep
-- so we need to run it twice
-- customHaskelineParser :: ParserInfo a -> ParserPrefs -> CompletionFunc IO
-- customHaskelineParser pinfo pprefs =
--   \(rleft, right) ->
--   let
--     leftArgs = words $ reverse rleft
--     -- TODO rename to str
--     fullArgs = reverse rleft ++ right
--     fullArgs' = words fullArgs ++ if trailingSpace then [""] else []
--   in do
--     if len fullArgs' > 1 then
--       generateHaskelineCompleterFromParserInfo (

-- generateHaskelineCompleterFromParserInfo = haskelineCompletionQuery
-- generateHaskelineCompleterFromParser pprefs (infoParser pinfo)

-- generateHaskelineCompleterFromParser :: ParserPrefs -> Parser a -> CompletionFunc IO
-- generateHaskelineCompleterFromParser parserPrefs (OptP opt) = generateHaskelineCompleterFromOption opt
-- generateHaskelineCompleterFromParser _ _ = error "undefined "

-- argument completeWith / complete
placeholderCompletion :: System.Console.Haskeline.Completion
placeholderCompletion = Completion "itworked" "display" False

constCompletionFunc :: CompletionFunc IO
constCompletionFunc (left, right) = pure ("worked", [placeholderCompletion])

-- generateHaskelineCompleterFromOption :: Option a -> CompletionFunc IO
-- generateHaskelineCompleterFromOption (Option main _properties) = generateHaskelineCompleterFromOptreader main

-- generateHaskelineCompleterFromOptreader :: OptReader a -> CompletionFunc IO
-- generateHaskelineCompleterFromOptreader (CmdReader mbGrpCommand arrStr func) =
--   \(rleft, right) -> let
--     filtered = filter (isPrefixOf prefix) arrStr
--     -- genCompletions :: String -> IO [Completion]
--     -- genCompletions prefix = map (genCompletion prefix)
--     -- "TODO show help for " ++
--     genCompletion entry =  Completion entry ( entry) True
--     prefix = reverse rleft
--     longestCommonPrefix entries = rleft
--     completions = map (genCompletion) filtered
--   in
--     -- TODO call execParserPure ParserInfo a
--     trace "completion called" (pure (
--     -- return longest common prefixes
--     "", completions
--     ))

-- -- TODO convert the C
-- -- generateHaskelineCompleterFromOptreader (ArgReader (CReader completer _)) =
-- generateHaskelineCompleterFromOptreader _ = error "undefined generateHaskelineCompleterFromOptreader"
