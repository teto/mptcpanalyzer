{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Commands.ListMptcp (
  piListMpTcpOpts
  , cmdListMptcpConnections
  , cmdListSubflows
)
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import Net.Mptcp

-- import Net.Mptcp.Types (MptcpConnection(..), MptcpSubflow, showMptcpConnection)

import qualified Control.Foldl as L
import Control.Lens hiding (argument)
import Data.Either (fromRight)
import Data.Maybe (catMaybes, fromJust)
import qualified Data.Set as Set
import Data.Word (Word16, Word32, Word64, Word8)
import Frames
import "mptcp-pm" Net.Tcp.Constants (TcpFlag(..))
import Options.Applicative
import qualified Pipes.Prelude as PP
import Polysemy (Embed, Member, Members, Sem)
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P

import Polysemy.Log (Log)
import qualified Polysemy.Log as Log

piListMpTcpOpts :: ParserInfo CommandArgs
piListMpTcpOpts = info (
    parserList <**> helper)
  ( progDesc "List MPTCP connections"
  )
  where
    parserList = ArgsListMpTcpConnections <$> switch ( long "detailed" <> help "detail connections")

piListMptcpSubflowOpts :: ParserInfo CommandArgs
piListMptcpSubflowOpts = info (
    parserList <**> helper)
  ( progDesc "List MPTCP connections"
  )
  where
    parserList = ArgsListSubflows <$> switch ( long "detailed" <> help "detail connections")


-- piListMptcpReinjectionsOpts :: ParserInfo CommandArgs
-- piListMptcpReinjectionsOpts = info (
--     parserList <**> helper)
--   ( progDesc "List MPTCP reinjections"
--   )
--   where
--     parserList = ArgsListSubflows <$> switch ( long "detailed" <> help "detail connections")

type SomeFrame = Frame Packet

-- TODO return MptcpStreamId instead
getMpTcpStreams :: SomeFrame -> [StreamIdMptcp]
getMpTcpStreams ps =
    catMaybes $
    L.fold L.nub (view mptcpStream <$> ps)

filterMptcpConnection :: SomeFrame -> StreamId Mptcp -> SomeFrame
filterMptcpConnection frame streamId =
  streamPackets
  where
    streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame




-- buildMptcpConnectionFromRow :: Packet -> TcpConnection
-- buildMptcpConnectionFromRow r =
  -- MptcpConnection {
    -- srcIp = r ^. ipSource
    -- , dstIp = r ^. ipDest
    -- , srcPort = r ^. tcpSrcPort
    -- , dstPort = r ^. tcpDestPort
    -- , priority = Nothing  -- for now
    -- , localId = 0
    -- , remoteId = 0
    -- , subflowInterface = Nothing
  -- }



cmdListSubflows :: (Members '[Log, P.State MyState, P.Trace, Cache, Embed IO] r)
  => Bool -- ^ Detailed
  -> Sem r RetCode
cmdListSubflows detailed = do
  P.trace "not implemented yet"
  return CMD.Continue

{-
-}
cmdListMptcpConnections ::
  (Members [Log, P.Trace, P.State MyState, Cache, P.Embed IO] r)
  => Bool -- ^ Detailed
  -> Sem r RetCode
cmdListMptcpConnections _detailed = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        P.trace "please load a pcap first"
        return CMD.Continue
      Just frame -> do
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.trace $ "Number of MPTCP connections " ++ show (length mptcpStreams)
        P.trace $ show mptcpStreams
        P.trace $ concatMap showEitherCon mptcpConnections
        -- >>
        return CMD.Continue
        where
          mptcpConnections :: [Either String MptcpConnection]
          mptcpConnections = map (fmap ffCon . buildMptcpConnectionFromStreamId frame ) mptcpStreams

          showEitherCon :: Either String MptcpConnection -> String
          showEitherCon (Left msg) = msg ++ "\n"
          showEitherCon (Right mptcpCon) = showConnection mptcpCon ++ "\n"

          mptcpStreams = getMpTcpStreams frame

