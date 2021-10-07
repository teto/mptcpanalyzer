{-# LANGUAGE DataKinds #-}
{-|
Module: Tshark.Live
Description : Load incrementally a PCAP into a frame
Maintainer  : matt
Portability : Linux
-}
module Tshark.Live (
  tsharkLoop
  , LiveStats(..)
)
where


import Tshark.Main (defaultTsharkPrefs, csvDelimiter)

import Data.Text as T
import GHC.IO.Handle
import Pipes ((>->))
import Pipes hiding (Proxy)
-- import Control.Monad.Primitive
import qualified Pipes as P
import qualified Pipes.Prelude as P
import qualified Pipes.Parse as P
import qualified Pipes.Safe as P
import Frames
import Frames.Exploration
import Frames.CSV (columnSeparator, tokenizeRow, defaultParser, pipeTableMaybeOpt, pipeTableEitherOpt, readRecEither, ReadRec, ParserOptions, headerOverride, readRow)
import Control.Monad (unless, liftM, when)
import           Data.Vinyl.Functor             (Compose (..), (:.))
import MptcpAnalyzer.Types (Packet, HostCols)
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import Control.Exception (try, IOException)
import Debug.Trace (traceShow, trace)
import Data.Maybe (isNothing)

import Net.Mptcp.Connection (MptcpConnection (MptcpConnection))
import Net.Mptcp (MptcpUnidirectionalStats)
import Control.Monad.State (StateT, modify')
import MptcpAnalyzer (FrameFiltered)
import Net.Tcp (TcpConnection)

-- --         +--------+-- A 'Producer' that yields 'String's
-- --         |        |
-- --         |        |      +-- Every monad transformer has a base monad.
-- --         |        |      |   This time the base monad is 'IO'.
-- --         |        |      |  
-- --         |        |      |  +-- Every monadic action has a return value.
-- --         |        |      |  |   This action returns '()' when finished
-- --         v        v      v  v
-- stdinLn :: Producer String IO ()
-- stdinLn = do
--     eof <- lift isEOF        -- 'lift' an 'IO' action from the base monad
--     unless eof $ do
--         res <- lift getLine
--         yield res            -- 'yield' the 'String'
--         stdinLn              -- Loop

-- loop :: Effect IO ()
-- loop = for stdinLn $ \x -> do  -- Read this like: "for str in stdinLn"
--     lift $ putStrLn x

-- | Opens a file (in 'P.MonadSafe') and repeatedly applies the given
-- function to the 'Handle' to obtain lines to yield. Adapted from the
-- moribund pipes-text package.
pipeLines :: P.MonadSafe m
          => (Handle -> IO (Either IOException T.Text))
          -> Handle
          -> P.Producer T.Text m ()
pipeLines pgetLine h =
  let loop = do txt <- P.liftIO (pgetLine h)
                case txt of
                  Left _e -> return ()
                  Right y -> P.yield y >> loop
  in loop

-- | Produce lines of 'T.Text'.
-- produceTextLines :: P.MonadSafe m => FilePath -> P.Producer T.Text m ()
-- produceTextLines = pipeLines (try . T.hGetLine)


-- copy/pasted 
pipeTableEitherOpt' :: (Monad m, ReadRec rs)
                   => ParserOptions
                   -> P.Pipe T.Text (Rec (Either T.Text :. ElField) rs) m ()
pipeTableEitherOpt' opts = do
  -- when (isNothing (headerOverride opts)) (() <$ P.await)
  P.map (readRow opts)




-- produceFrameChunks
-- inCoreAoS
-- --capture-comment
-- TODO return the frame/ stats
tsharkLoop :: Handle -> Effect (StateT LiveStats IO) ()
tsharkLoop hout = do

  ls <- for (tsharkProducer hout) $ \(x) -> do
      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame ::  FrameRec HostCols) <- liftIO $ inCoreAoS (yield x >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      liftIO $ putStrLn $ "test: " ++  T.unpack x
      liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      liftIO $ putStrLn $ "length " ++ show ( frameLength frame)
      modify' (\stats -> stats {  lsPackets = lsPackets stats + 1})
      -- lift $ print liveStats

  pure ls

  where
    -- tokenize = tokenizeRow popts
    popts = defaultParser {
          columnSeparator = T.pack $ [csvDelimiter defaultTsharkPrefs]
        }
    -- readRecEither
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

    recEither = rtraverse getCompose



-- type UpdateFrameFunc a b = Frame a -> Frame a -> (Frame a, b)

-- | Hold information on a connection
data LiveStats = LiveStats {
  -- lsCon :: MptcpConnection,
  lsStats :: MptcpUnidirectionalStats
  , lsPackets :: Int
  -- , lsFrame :: FrameFiltered TcpConnection Packet
  , lsFrame :: FrameFiltered TcpConnection Packet
  }


tsharkProducer :: Handle -> Producer Text (StateT LiveStats IO) ()
tsharkProducer hout = do
  -- let liveStats = LiveStats mempty 0 mempty
  eof <- liftIO $ hIsEOF hout
  if eof == True then
    return ()
  else do
    output <- liftIO $ hGetLine hout
    yield (T.pack output)
    tsharkProducer hout
  -- return ls

---- Accept as input the different handles
--readTsharkOutputAndPlotIt :: Handle -> Handle -> IO ()
--readTsharkOutputAndPlotIt hout herr = do
--  -- use pipeTableEitherOpt to parse 
--  output <- hGetContents hout
--  putStrLn output
