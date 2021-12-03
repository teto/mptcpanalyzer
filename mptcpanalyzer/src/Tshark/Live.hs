{-# LANGUAGE DataKinds #-}
{-|
Module: Tshark.Live
Description : Load incrementally a PCAP into a frame
Maintainer  : matt
Portability : Linux
-}
module Tshark.Live (
    showLiveStatsTcp
  , LiveStats(..)
  , LiveStatsTcp
  , LiveStatsMptcp
  , CaptureSettingsMptcp(..)
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
import qualified Data.Map.Strict as Map
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
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Pcap (addTcpDestinationsToAFrame)
import MptcpAnalyzer.Types (FrameFiltered(FrameTcp))
import Net.Mptcp (MptcpUnidirectionalStats)
import Net.Mptcp.Connection (MptcpConnection(MptcpConnection))
import Net.Mptcp.Stats (MptcpUnidirectionalStats, showMptcpUnidirectionalStats)
import Net.Tcp (TcpConnection)
import Net.Tcp.Stats
       (TcpUnidirectionalStats, getTcpStats, showTcpUnidirectionalStats)
import System.Console.ANSI
import System.IO (stdout)
import Net.Mptcp.Connection
import qualified Data.Set as Set


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

-- | Show live stats TCP
-- showLiveStatsTcp :: LiveStatsTcp -> Text
-- showLiveStatsTcp stats = T.unlines [
--   showLiveStats (SomeStats stats)
--   , showTcpUnidirectionalStats (lsStats stats)
--   ]

showLiveStatsTcp :: LiveStatsTcp -> Text
showLiveStatsTcp  liveStats =
      T.unlines ([
            showLiveStats (SomeStats liveStats)
            ]
            -- ++ if lsDestination liveStats == RoleServer then else []
            ++ ["Showing towards server:", showTcpUnidirectionalStats (lsForwardStats liveStats)]
            -- ++ if lsDestination liveStats == RoleClient then else []
            ++ ["Showing towards client:", showTcpUnidirectionalStats (lsBackwardStats liveStats)]
            )



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
  lsForwardStats :: stats
  , lsBackwardStats :: stats
  -- keep to check everything worked fine? else we can retreive the count from lsFrame
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

-- should be richer
data CaptureSettingsMptcp = CaptureSettingsMptcp {
    -- tcpStreamId
    lsmMaster :: Maybe MptcpSubflow
  , lsmSubflows :: Map.Map MptcpSubflow MptcpUnidirectionalStats
  , lsmStats :: LiveStatsMptcp
  }


data SomeStats where
  SomeStats :: LiveStats a b c -> SomeStats

tshow :: Show a => a -> T.Text
tshow = T.pack . Prelude.show


-- showLiveStatsMptcp :: LiveStatsMptcp -> Text
-- showLiveStatsMptcp stats =
--   showLiveStats (SomeStats stats) <> showMptcpUnidirectionalStats (lsStats stats)

showLiveStats :: SomeStats -> Text
showLiveStats (SomeStats liveStats) =
  T.unlines [
    "Number of packets: " <> tshow (lsPackets liveStats)
  ]


-- tsharkProducer :: Handle -> Producer Text TsharkMonad ()
-- tsharkProducer hout = do
--     liftIO $ trace ("show hout " ++ show hout) hSetBuffering hout NoBuffering
--     output <- liftIO $ trace "hgetline" hGetLine hout
--     trace "yield" yield (T.pack output)
--     tsharkProducer hout

---- Accept as input the different handles
--readTsharkOutputAndPlotIt :: Handle -> Handle -> IO ()
--readTsharkOutputAndPlotIt hout herr = do
--  -- use pipeTableEitherOpt to parse
--  output <- hGetContents hout
--  putStrLn output
