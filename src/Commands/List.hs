{-# LANGUAGE FlexibleContexts           #-}

module Commands.List
where

-- import Data.Text
-- import Net.Tcp
import qualified Commands.Utils         as CMD
import Options.Applicative
import Pcap
import Frames
import Control.Lens hiding (argument)
import Control.Monad.Trans (liftIO)
import Control.Monad.State (get)
import Utils


type MptcpStreamId = Int
type TcpStreamId = Int

-- This 
data ParserListSubflows = ParserListSubflows {
  full :: Bool,
  streamId :: MptcpStreamId
}

-- |TODO pass the loaded pcap to have a complete filterWith
-- listSubflowParser = 

parserSubflow :: Parser ParserListSubflows
parserSubflow = ParserListSubflows <$> (switch
          ( long "full"
         <> help "Print details for each subflow" ))
      <*> argument auto (
          help "Show version"
          -- TODO pass a default
          )

optsListSubflows :: ParserInfo ParserListSubflows
optsListSubflows = info (parserSubflow <**> helper)
  ( fullDesc
  <> progDesc "List subflows of an MPTCP connection"
  <> header ""
  <> footer ""
  )

-- listTcpConnections :: [TcpConnection] -> Text
-- listTcpConnections conns =
--         streams = self.data.groupby("tcpstream")
--         (show len connections) ++ " tcp connection(s)" ++ map (\
--         where
          -- for tcpstream, group in streams:
          --     con = TcpConnection.build_from_dataframe(self.data, tcpstream)
          --     self.poutput(str(con))
-- checkIfLoaded :: CMD.CommandConstraint m => [String] -> m CMD.RetCode
-- checkIfLoaded = 
    -- putStrLn "not loaded"

listTcpConnections :: CMD.CommandConstraint m => [String] -> m CMD.RetCode
listTcpConnections params = do
    state <- get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> liftIO $ putStrLn "please load a pcap first" >> return CMD.Continue
      Just frame -> do
                    liftIO $ putStrLn $ "Number of rows " ++ show (frameLength frame)
                    >> return CMD.Continue
                    -- liftIO $ listTcpConnectionsInFrame frame >> return CMD.Continue

    -- liftIO $ putStrLn "list tcp connections:" >> return CMD.Continue
  

listTcpConnectionsInFrame :: PcapFrame -> IO ()
listTcpConnectionsInFrame frame = do
  putStrLn "Listing tcp connections"
  let streamIds = getTcpStream frame
  mapM_ (\x -> putStrLn $ show x) streamIds
  return ()

  -- L.fold L.minimum (view age <$> ms)
  -- L.fold
  -- putStrLn $ show $ rcast @'[TcpStream] $ frameRow frame 0
  -- let l =  L.fold L.nub (view tcpstream <$> frame)
-- listMptcpConnections :: PcapFrame -> MyStack IO ()
-- listMptcpConnections frame = do
--     return ()


--
cmdMptcpSummary :: CMD.CommandConstraint m => [String] -> m CMD.RetCode
cmdMptcpSummary = undefined
