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
  , completePath
  , readFilename
  -- , generateHaskelineCompleterFromOption
)
where

import Options.Applicative
import System.Console.Haskeline (CompletionFunc, completeFilename, noCompletion, Completion(..))
import System.Console.Haskeline.Completion (listFiles)
import Options.Applicative.Types
import Data.List (isPrefixOf, stripPrefix, isSuffixOf)
import Debug.Trace
import Options.Applicative.Help (Doc)
import Options.Applicative.Help.Pretty (displayS)
import Options.Applicative.Help (renderPretty)
import Data.Maybe (fromMaybe, listToMaybe, fromJust)
import Options.Applicative.Common
import Options.Applicative.Internal hiding (Completion)
import Options.Applicative.Help.Chunk
import Data.Char (isSpace)
-- import Options.Applicative.Help (parserHelp)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix (fileExist)

defaultCompleteFunc :: CompletionFunc IO
defaultCompleteFunc = completeFilename


-- | We use unsafePerformIO to work around optparse-applicative limitation
readFilename :: String -> Either String FilePath
readFilename path =
  let exists = unsafePerformIO $ fileExist path
  in
  case exists of
    True -> trace "right path" Right path
    False -> trace ("path " ++ path ++ " DOES NOT EXIST")
      Left "Path does not exist" 
      -- throwE "path does not exist"


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
  (_, completions) <- completeFilename (reverse entry, "")
  let completions' = map replacement completions
  putStrLn $ "completePath called !! with entry: [" ++ entry ++ "]"
  return $ trace ("completions: " ++ show completions) completions'

-- runCompletion
--
-- bashCompletionQuery :: ParserInfo a -> ParserPrefs -> Richness -> [String] -> Int -> String -> IO [String]
-- bashCompletionQuery pinfo pprefs richness ws i _ = case runCompletion compl pprefs of

-- myRunCompletion :: Completion r -> ParserPrefs -> Maybe (Either (SomeParser, ArgPolicy) Completer)
-- myRunCompletion (Completion c) prefs = case runReaderT (runExceptT c) prefs of
--   ComplResult r -> Nothing
--   ComplParser p' a' -> Just $ Left (p', a')
--   ComplOption compl -> Just $ Right compl

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
  Just (Left (SomeParser p, a)) -> trace "listing options\n" list_options a p
  -- terminal case
  Just (Right c) -> trace "terminal completer\n" run_completer c
  Nothing -> trace "runCompletion into Nothing\n" return []
  where
    --current word
    -- runParserInfo te renvoie une (Completion a)
    -- drop 1 looks necesary here ?
    compl = traceShow ("Passing args " ++ show ws ++ "\n") runParserInfo pinfo ws
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
    opt_completions argPolicy reachability opt = case trace ("argPolicy " ++ show argPolicy ++ "\n") optMain opt of
      OptReader ns _ _
         | argPolicy /= AllPositionals -> trace "unreachable OptReader\n" return . add_opt_help opt $ show_names ns
         | otherwise -> trace "optreader\n" return []
      FlagReader ns _
         | argPolicy /= AllPositionals -> trace "unreachableflag reader\n" return . add_opt_help opt $ show_names ns
         | otherwise -> trace "flagreader\n" return []
      ArgReader rdr
         | argumentIsUnreachable reachability -> trace "unreachable\n " return []
         -- TODO restore arg Reader with file autocomplete
         --  | otherwise -> return []
         | otherwise -> trace "argreader\n" run_completer (crCompleter rdr)
         -- >>= \x -> return $ Completion x "argreader help" True
      CmdReader _ ns p
         | argumentIsUnreachable reachability -> trace "unreachable cmdreader\n" return []
         | otherwise -> trace "cmdreader\n" return . add_cmd_help p $ filter_names ns

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
    run_completer c = trace ("running completer against " ++ currentArg) runCompleter c currentArg >>= \x -> return $ map (\y -> Completion y "TODO help" True) x

    currentArg :: String
    currentArg = case ws of
      [] -> ""
      ws' -> last ws'
    -- (ws', ws'') = splitAt i ws

    -- is_completion :: String -> Bool
    -- is_completion = 
    --   case trace ("comparing ws''" ++ show ws'' ) ws'' of
    --     w:_ -> trace ("checking if " ++ w ++ " is a prefix of ") isPrefixOf w
    --     _ -> trace "is_completion=true" const False

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


    pure (reverse leftRes,  map (
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
