--defaultPrefs :: ParserPrefs
-- ParserPrefs
-- execParserPure :: 
-- execParserPure puis on recupere le resultat ParserResult puis on affiche la completion
-- customExecParser
-- handleParseResult

-- execParserPure :: ParserPrefs       -- ^ Global preferences for this parser
--                -> ParserInfo a      -- ^ Description of the program to run
--                -> [String]          -- ^ Program arguments
--                -> ParserResult a
-- handleParseResult

-- dealWithParseResult :: ParserResult a
-- il faudrait qu'il me retourne le champ sur lequel il foire et comme ca je peux recuperer son completer
-- s'il n'a pas de completer on affiche son aide
-- on peut aussi faire un mapping entre les action bash et les completer de repline

-- mainTest :: String
-- mainTest =
--       handleRes result
--     where
--         result = execParserPure parserPrefs parserInfo cmdArgs
--         parserPrefs = defaultPrefs
--         -- "test"
--         cmdArgs = [ "mama", "--hello=toto"  ]
--         parserInfo = info simpleParser fullDesc
--         handleRes :: ParserResult SimpleData -> String
--         handleRes (CompletionInvoked compl) = "toto"
--         handleRes (Failure failure) = "failed"
--         handleRes (Success x) = "Success"


-- mainHaskeline :: IO ()
-- mainHaskeline = do
--   let haskelineSettings = defaultSettings
--   -- SETUP LOGGING (https://gist.github.com/ijt/1052896)
--   -- streamHandler vs verboseStreamHandler

--   -- logMsg "main" InfoS  "Parsing command line..."
--   options <- execParser opts
--   let logContext = mempty
--   let state = (MyState "main" logContext)


--   runInputT haskelineSettings loop
--   where
--       loop :: InputT IO ()
--       loop = do
--           minput <- getInputLine "% "
--           case minput of
--               Nothing -> return ()
--               Just "quit" -> return ()
--               Just input -> do
--                     outputStrLn $ "Input was: " ++ input
--                     loop


 
-- odasd
-- toto

