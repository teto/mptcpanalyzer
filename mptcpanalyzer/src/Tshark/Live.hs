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
  , LiveStatsTcp
  , LiveStatsMptcp
)
where


import Tshark.Main (csvDelimiter, defaultTsharkPrefs)

import Data.Text as T
import GHC.IO.Handle
import Pipes ((>->))
import Pipes hiding (Proxy)
-- import Control.Monad.Primitive
import Control.Exception (IOException, try)
import Control.Monad (liftM, unless, when)
import Data.Maybe (isNothing)
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import Data.Vinyl.Functor (Compose(..), (:.))
import Debug.Trace (trace, traceShow, traceShowId)
import Frames
import Frames.CSV
       ( ParserOptions
       , ReadRec
       , columnSeparator
       , defaultParser
       , headerOverride
       , pipeTableEitherOpt
       , pipeTableMaybeOpt
       , readRecEither
       , readRow
       , tokenizeRow
       )
import Frames.Exploration
import MptcpAnalyzer.Types (HostCols, Packet)
import qualified Pipes as P
import qualified Pipes.Parse as P
import qualified Pipes.Prelude as P
import qualified Pipes.Safe as P

import Control.Monad.State (MonadState(get), StateT, gets, modify')
import Control.Monad.State.Lazy (execStateT)
import Data.Text.IO (hPutStrLn)
import MptcpAnalyzer (FrameFiltered(ffFrame))
import Net.Mptcp (MptcpUnidirectionalStats)
import Net.Mptcp.Connection (MptcpConnection(MptcpConnection))
import Net.Mptcp.Stats (MptcpUnidirectionalStats, showMptcpUnidirectionalStats)
import Net.Tcp (TcpConnection)
import Net.Tcp.Stats
       (TcpUnidirectionalStats, getTcpStats, showTcpUnidirectionalStats)
import Pipes.Prelude (fromHandle)
import System.Console.ANSI
import System.IO (stdout)
import MptcpAnalyzer.Types (FrameFiltered(FrameTcp))
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Pcap (addTcpDestinationsToAFrame)


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


type TsharkMonad = (StateT (LiveStatsTcp) IO)
-- type TsharkMonad = IO

-- produceFrameChunks
-- inCoreAoS
-- --capture-comment
-- TODO return the frame/ stats
tsharkLoop :: Handle -> Effect TsharkMonad ()
tsharkLoop hout = do
  -- let initialLiveStats :: LiveStatsTcp = LiveStats mempty 0 mempty

  -- hSetBuffering stdout NoBuffering
  -- ls <- for (tsharkProducer hout) $ \x -> do
  ls <- for (fromHandle hout) $ \x -> do

      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame :: FrameRec HostCols) <- liftIO $ inCoreAoS (yield (T.pack x) >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      -- liftIO $ putStrLn $ "test: "
      -- liftIO $ putStrLn $ "test: " ++  x
      -- liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      stFrame <- gets lsFrame
      modify' (\stats -> stats {
        lsPackets = lsPackets stats + 1
        , lsFrame = (lsFrame stats)  <> frame
        , lsStats = (lsStats stats) <> (getTcpStats ( addTcpDestinationsToAFrame (FrameTcp (lsConnection stats) frame)) RoleClient)
        })
      liftIO $ cursorUp 1
      liveStats <- get
      liftIO clearFromCursorToScreenEnd
      let output = showLiveStatsTcp liveStats
      liftIO $ cursorUp $ Prelude.length $ T.lines output
      liftIO $ (putStrLn . T.unpack) output
      -- liftIO $ putStrLn $ "length " ++ show (frameLength stFrame)
      -- lift $ hPutStrLn stdout "test"

  pure ls
  -- pure ()

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
-- data LiveStats = LiveStats {
--   -- lsCon :: MptcpConnection,
--   lsStats :: MptcpUnidirectionalStats
--   , lsPackets :: Int
--   -- , lsFrame :: FrameFiltered TcpConnection Packet
--   , lsFrame :: FrameRec HostCols
--   }

-- TODO should be instance of a Monoid !
-- | for now unidirectional ?
data LiveStats stats con packet = LiveStats {
  -- lsCon :: MptcpConnection,
  lsStats :: stats
  , lsPackets :: Int
  , lsConnection :: con
  , lsDestination :: ConnectionRole
  -- , lsConnection :: TcpConnection
  , lsFrame :: Frame packet
  -- , lsFrame :: FrameFiltered con packet
  , lsHasFinished :: Bool
  -- ^ True once it sees a FIN
  -- , lsFrame :: FrameRec HostCols
  }

type LiveStatsTcp = LiveStats TcpUnidirectionalStats TcpConnection Packet
type LiveStatsMptcp = LiveStats MptcpUnidirectionalStats MptcpConnection Packet

data SomeStats where
  SomeStats :: LiveStats a b c -> SomeStats

tshow :: Show a => a -> T.Text
tshow = T.pack . Prelude.show

showLiveStatsTcp :: LiveStatsTcp -> Text
showLiveStatsTcp stats =
  showLiveStats (SomeStats stats) <> showTcpUnidirectionalStats (lsStats stats)

showLiveStatsMptcp :: LiveStatsMptcp -> Text
showLiveStatsMptcp stats =
  showLiveStats (SomeStats stats) <> showMptcpUnidirectionalStats (lsStats stats)

showLiveStats :: SomeStats -> Text
showLiveStats (SomeStats liveStats) =
  T.unlines [
    "Number of packets: " <> tshow (lsPackets liveStats)
    , tshow (lsPackets liveStats)
  ]


tsharkProducer :: Handle -> Producer Text TsharkMonad ()
tsharkProducer hout = do
    liftIO $ trace ("show hout " ++ show hout) hSetBuffering hout NoBuffering
    output <- liftIO $ trace "hgetline" hGetLine hout
    -- liftIO $ putStrLn output
    trace "yield" yield (T.pack output)
    tsharkProducer hout
  -- return ls

---- Accept as input the different handles
--readTsharkOutputAndPlotIt :: Handle -> Handle -> IO ()
--readTsharkOutputAndPlotIt hout herr = do
--  -- use pipeTableEitherOpt to parse
--  output <- hGetContents hout
--  putStrLn output
