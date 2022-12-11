{-|
Module: MptcpAnalyzer.Pcap
Maintainer  : matt
License     : GPL-3

Pot-pourri
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports #-}
module MptcpAnalyzer.Pcap (
    addTcpDestToFrame
    , addMptcpDestToFrame
    , addMptcpDest
    , addTcpDestinationsToAFrame
    , buildTcpConnectionFromStreamId
    , buildMptcpConnectionFromStreamId
    , defaultParserOptions
    , genTcpDestFrame
    , genTcpDestFrameFromAFrame
    , exportToCsv
    , loadRows
    , getTcpStreams
    , getMptcpStreams
    , buildSubflowFromRecord
    , buildSubflowFromTcpStreamId
    , buildTcpConnectionFromRecord
    , buildTcpConnectionTupleFromRecord

    , genMptcpEndpointConfigFromRow 
    -- TODO remove ? use instance instead
    , showMptcpSubflowText
    , StreamConnection(..)
    , showConnection
    , scoreTcpCon
    , scoreMptcpCon
    -- , showMptcpSubflowText
    )
where


import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Text
import Net.Mptcp.Connection
import Net.Tcp
import Net.Stream
import Net.Tcp.Constants (TcpFlag(..))
import Tshark.Fields
import Tshark.TH

-- hackage
import Control.Lens ((^.))
import Data.Kind (Type)
import Data.Monoid (First(..))
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Vector as V
import Frames
import Frames.CSV
       ( ParserOptions(..)
       , QuotingMode(..)
       , ReadRec
       , pipeTableEitherOpt
       , produceTextLines
       , readFileLatin1Ln
       , readTableMaybeOpt
       )
import Frames.Col
import Frames.ColumnTypeable (Parseable(..), Parsed(..), parseIntish)
import Frames.ShowCSV
import Frames.TH
import System.Exit
import System.IO
       ( BufferMode(LineBuffering)
       , Handle
       , SeekMode(AbsoluteSeek)
       , hGetContents
       , hSeek
       , hSetBuffering
       )
import System.Process
-- for Record
-- import Frames.Rec (Record(..))
import Data.List (intercalate)
import Net.IP
-- for symbol
-- import GHC.Types
import qualified Control.Foldl as L
import qualified Data.Set as Set
-- import Language.Haskell.TH
-- import Language.Haskell.TH.Syntax
-- import Lens.Micro
-- import Lens.Micro.Extras
import Control.Lens
import qualified Data.Foldable as F
import Data.Maybe (catMaybes, fromJust, isNothing)
import Data.Vinyl (ElField(..), Rec(..), rapply, rmapX, xrec)
import Data.Vinyl.Class.Method
import Data.Vinyl.Functor (Compose(..), (:.))
import Data.Word (Word16, Word32, Word64, Word8)
import GHC.Base (Symbol)
import GHC.List (foldl')
import GHC.TypeLits (KnownSymbol)
import Numeric (readHex)
import Pipes (Producer, cat, (>->))
import qualified Pipes.Prelude as P
-- import qualified Frames.InCore
import Control.Exception (assert)
import Data.Either (lefts, rights)
import qualified Data.Map as Map
import Debug.Trace
import qualified Frames.InCore as I
import GHC.IO.Handle (hClose)
import System.Environment (getEnvironment)
import System.IO.Temp
import Tshark.Main

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.


-- on veut la generer
-- [[t|Ident Int|], [t|Happiness|]]
-- tableTypesExplicit' :: [Q Type] -> RowGen a -> FilePath -> DecsQ
-- tableTypesExplicit'

-- tableTypesExplicit'
--   (getTypes baseFields)
--   -- [ Field Word64 ]
--   -- [[t| Word64|]]
--   ((rowGen "data/test-1col.csv")
--   { rowTypeName = "Packet"
--         , separator = ","
--         -- TODO I could generate it as well
--         -- , columnNames
--     })
--     -- path
--     "data/test-simple.csv"



-- shadow type to know if it was filtered or not
-- Make it a record ?
-- first argument allows to override csv header ("headerOverride")
defaultParserOptions :: ParserOptions
defaultParserOptions = ParserOptions Nothing (T.pack [csvDelimiter defaultTsharkPrefs]) NoQuoting

-- nub => remove duplicates
-- or just get the column
getTcpStreams :: FrameRec HostCols -> [StreamIdTcp]
getTcpStreams ps = L.fold L.nub (view tcpStream <$> ps)

-- | to list
getMptcpStreams :: FrameRec HostCols -> [StreamId Mptcp]
getMptcpStreams ps = L.fold L.nub $ catMaybes $ F.toList (view mptcpStream <$> ps)
-- filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame



{- Export to CSV
sets WIRESHARK_CONFIG_DIR so that the user profile doesn't influence the output
-}
exportToCsv ::
  TsharkParams
  -> FilePath  -- ^Path to the pcap
  -> Handle -- ^ temporary file
-- ^See haskell:readCreateProcessWithExitCode
  -> IO (ExitCode, String)
exportToCsv params pcapPath tmpFileHandle = do
    curEnv <- getEnvironment
    withSystemTempFile "tshark-profile" $ \tempDir _ -> do
      let
          (RawCommand bin args) = generateCsvCommand fields (Right pcapPath) (params )
          createProc :: CreateProcess
          createProc = (proc bin args) {
              std_err = CreatePipe,
              std_out = UseHandle tmpFileHandle,
              env = Just $ curEnv ++ [ ("WIRESHARK_CONFIG_DIR", tempDir) ],
              delegate_ctlc = True
              }
      putStrLn $ "Exporting fields " ++ show fields
      putStrLn $ "Command run: " ++ show (RawCommand bin args)
      -- TODO redirect stdout towards the out handle
      hSetBuffering tmpFileHandle LineBuffering
      hSeek tmpFileHandle AbsoluteSeek 0 >> T.hPutStrLn tmpFileHandle fieldHeader
      (_, _, Just herr, ph) <-  createProcess_ "error" createProc
      exitCode <- waitForProcess ph
      -- TODO do it only in case of error ?
      err <- hGetContents herr
      hClose herr
      return (exitCode, err)
    where
      fields :: [T.Text]
      fields = Map.elems $ Map.map tfieldFullname baseFields

      csvSeparator = T.pack [csvDelimiter params]
      fieldHeader :: Text
      fieldHeader = T.intercalate csvSeparator (Map.keys baseFields)


loadRows :: (I.RecVec a, ReadRec a) => FilePath -> IO (FrameRec a)
loadRows path = inCoreAoS (
  eitherProcessed path
  )


-- type ManEither = Rec (Either T.Text :. ElField) (RecordColumns Packet)

-- pipteTable will tokenize on its own
-- loadRowsEither :: MonadSafe m => FilePath -> Producer ManEither m ()
-- loadRowsEither path =  produceTextLines path >-> pipeTableEitherOpt defaultParserOptions

{- |Load rows and errors when it can't load a specific line
-}
eitherProcessed :: (ReadRec a, MonadSafe m) => FilePath -> Producer (Record a) m ()
eitherProcessed path = produceTextLines path
  >-> pipeTableEitherOpt defaultParserOptions >-> P.map fromEither
  where
    -- fromEither :: Rec (Either Text :. ElField) (RecordColumns Packet) -> Packet
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

    recEither = rtraverse getCompose

-- | Undistribute 'Maybe' from a 'Rec' 'Maybe'. This is just a
-- specific usage of 'rtraverse', but it is quite common.
-- recEither :: Rec (Either Text :. ElField) cs -> Either Text (Record cs)
-- recEither = rtraverse getCompose

-- data TsharkPrefs = TsharkPrefs {
--     analyzeTcpSeq :: Bool
--     , analyzeMptcp :: Bool
--     , mptcpRelSeq :: Bool
--     , analyzeMptcp :: Bool
--   } deriving Show

{-
-}
-- getTcpFrame :: FrameRec HostCols -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
-- getTcpFrame = buildTcpConnectionFromStreamId

-- | For now assume the packet is the first syn from client to server
-- TODO this is wrong, assumes source ip is client, convert to return a TcpConnectionOriented
buildTcpConnectionFromRecord :: (
  IpFields rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
  ) => Record rs -> TcpConnection
buildTcpConnectionFromRecord r =
  TcpConnection {
      clientIp = r ^. ipSource
    , serverIp = r ^. ipDest
    , clientPort = r ^. tcpSrcPort
    , serverPort = r ^. tcpDestPort
    , streamId = r ^. tcpStream
  }

buildTcpConnectionTupleFromRecord :: (
  IpFields rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
  ) => Record rs -> TcpConnectionOriented
buildTcpConnectionTupleFromRecord r =
  TcpConnectionOriented {
      conTcpSourceIp = r ^. ipSource
    , conTcpDestinationIp = r ^. ipDest
    , conTcpSourcePort = r ^. tcpSrcPort
    , conTcpDestinationPort = r ^. tcpDestPort
    -- , streamId = r ^. tcpStream
  }

{- Builds a Tcp connection from a non filtered frame
-}
buildTcpConnectionFromStreamId ::
  FrameRec HostCols
  -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
buildTcpConnectionFromStreamId frame streamId' =
    if frameLength synPackets < 1 then
      Left $ "No packet with any SYN flag for tcp.stream " ++ show streamId'
    else
      -- TODO check who is client
      Right $ FrameTcp (buildTcpConnectionFromRecord $ frameRow synPackets 0) streamPackets
    where
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId') frame
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets


-- |
-- buildMasterSubflowFromRecord ::


-- | Builds
-- should expect a filteredFrame with MPTCP
-- buildSubflowFromTcpStreamId :: FrameFiltered TcpConnection Packet -> StreamId Tcp -> Either String (FrameFiltered MptcpSubflow Packet)
buildSubflowFromRecord :: Packet -> MptcpSubflow
buildSubflowFromRecord row =
  MptcpSubflow {
          connection = sfCon
        -- TODO ignore if it's master token
        , joinToken = row ^. mptcpRecvToken
        , priority = Nothing
        -- TODO
        , localId = 0
        , remoteId = 0
        -- todo load it from row
        , interface = Nothing
      }
  where
      sfCon = buildTcpConnectionFromRecord row


buildSubflowFromTcpStreamId ::
  (
  rs ⊆ HostCols
  , I.RecVec rs
  , TcpFlags ∈ rs , TcpStream ∈ rs, MptcpRecvToken ∈ rs
  , IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
  )
  => FrameRec rs
  -> StreamId Tcp
  -> Either String (FrameFiltered MptcpSubflow (Record rs))
buildSubflowFromTcpStreamId frame streamId' =
    if frameLength synPackets < 1 then
      Left $ "No packet with any SYN flag for tcp.stream " ++ show streamId'
    else
      -- TODO check who is client
      Right $ FrameTcp sf streamPackets
    where
      syn0 = frameRow synPackets 0
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId') frame
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      sfCon = buildTcpConnectionFromRecord syn0
      -- rcvToken
      sf = MptcpSubflow {
        connection = sfCon
        -- TODO ignore if it's master token
        , joinToken = syn0 ^. mptcpRecvToken
        , priority = Nothing
        , localId = 0
        , remoteId = 0
        , interface = Nothing
      }

-- | Sets mptcp role column
-- TODO maybe je devrais juste generer un
addMptcpDest ::
    (
      -- Frames.InCore.RecVec rs,
      -- HostCols ⊆ rs
      -- MptcpStream ∈ rs, TcpStream  ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs
      -- rs = HostCols
      ) =>
      Frame (Record HostCols)
      -> MptcpConnection
      -> FrameRec  (
            MptcpDest ': TcpDest ': HostCols
          )
addMptcpDest frame con =
    -- foldl' (\tframe sf -> addDestToFrame tframe sf) startingFrame subflows
    mconcat subflowFrames
    where
      -- filteredFrame = filterFrame  (\x -> x ^. mptcpStream == Just (mpconStreamId con)) frame
      -- filteredFrame = filterFrame  (\x -> (rgetField @MptcpStream x) == Just (mpconStreamId con)) frame

      subflowFrames = map addDestsToSubflowFrames subflows

      addDestsToSubflowFrames sf = addMptcpDestToFrame' (addTcpDestToFrame frame sf.connection) sf

      addMptcpDest' role x = Col role :& x

      addMptcpDestToFrame' frame' sf = fmap (addMptcpDest' (getMptcpDest con sf)) frame'

      -- startingFrame = fmap setTempDests frame
      -- setTempDests :: Record rs -> Record ( MptcpDest ': TcpDest ': rs)
      -- setTempDests x = Col RoleClient :& Col RoleClient :& x
      -- addMptcpDestToRec x role = Col role :& x
      subflows = Set.toList $  con.subflows

addMptcpDestToFrame :: MptcpConnection -> FrameFiltered MptcpSubflow Packet -> FrameRec '[MptcpDest]
addMptcpDestToFrame mpcon (FrameTcp sf frame) = fmap (addMptcpDest' (getMptcpDest mpcon sf)) frame
  where
      addMptcpDest' role _x = Col role :& RNil


getMptcpDest :: MptcpConnection -> MptcpSubflow -> ConnectionRole
getMptcpDest mptcpCon sf = case sf.joinToken  of
  -- master subflow, dest is by definition the server
  Nothing -> RoleServer
  Just token -> if token == mptcpCon.serverConfig.token then
    RoleServer
  else
    RoleClient


-- | Sets TCP role column
-- append a column with a value role
-- Todo accept a 'FrameFiltered'
-- I want to check it is included
-- TODO add an unsafe version ?
addTcpDestToFrame :: (
  I.RecVec rs
  ,IpSource ∈ rs, IpDest ∈ rs
  , IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs
  , TcpStream ∈ rs
  )
    => FrameRec rs
    -> TcpConnection
    -> FrameRec ( TcpDest ': rs )
addTcpDestToFrame frame con = do
  assert
    -- check that they all belong to the same stream
    (length ( L.fold L.nub (view tcpStream <$> frame)) == 1)
    fmap (\x -> addTcpDestToRec x (computeTcpDest x con)) streamFrame
  where
    streamFrame = frame


-- | Generates a frame with a single column containing the TcpDest
genTcpDestFrame :: (
  I.RecVec rs
  , IpSource ∈ rs, IpDest ∈ rs
  , TcpSrcPort ∈ rs, TcpDestPort ∈ rs
  , TcpStream ∈ rs
  )
    => FrameRec rs
    -> TcpConnection
    -> FrameRec '[TcpDest]
genTcpDestFrame frame con = fmap (\x -> Col (computeTcpDest x con) :& RNil) streamFrame
    where
      streamFrame = filterFrame  (\x -> rgetField @TcpStream x == streamId con) frame

genTcpDestFrameFromAFrame :: (
  I.RecVec rs
  , IpSource ∈ rs, IpDest ∈ rs
  , TcpSrcPort ∈ rs, TcpDestPort ∈ rs
  , TcpStream ∈ rs
  )
    => FrameFiltered TcpConnection (Record rs)
    -> FrameRec '[TcpDest]
genTcpDestFrameFromAFrame aframe = genTcpDestFrame aframe.ffFrame aframe.ffCon


computeTcpDest :: (
  TcpStream ∈ rs
  , IpFields rs
  , TcpSrcPort ∈ rs
  , TcpDestPort ∈ rs
  ) => Record rs
  -> TcpConnection -> ConnectionRole
computeTcpDest x con  = if rgetField @IpSource x == con.clientIp
                && rgetField @IpDest x == con.serverIp
                && rgetField @TcpSrcPort x == con.clientPort
                && rgetField @TcpDestPort x == con.serverPort
                && rgetField @TcpDestPort x == con.serverPort
                -- TODO should error if not the same streamId
                -- && (rgetField @TcpStream x) == (streamId con)
        then RoleServer else RoleClient


-- | TODO
-- See @addTcpDestToFrame@
addTcpDestinationsToAFrame :: (
  -- HostCols ⊆ rs,
  I.RecVec rs
  -- , HostCols <: rs
  -- , HostCols ∈ rs
  , IpFields rs
  , TcpFields rs)
  => FrameFiltered TcpConnection (Record rs)
  -> FrameFiltered TcpConnection (Record (TcpDest ': rs))
addTcpDestinationsToAFrame aframe =
  aframe { ffFrame = addDestinationsToFrame' aframe.ffCon}
  where
    frame = aframe.ffFrame
    addDestinationsToFrame' con = addTcpDestToFrame frame con

-- append a field with a value role
addTcpDestToRec :: (TcpStream ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs)
  => Record rs -> ConnectionRole ->  Record  ( TcpDest ': rs )
addTcpDestToRec x role = (Col role) :& x


-- TODO take into account the different mptcp versions ?
genMptcpEndpointConfigFromRow :: Packet -> Maybe MptcpEndpointConfiguration
genMptcpEndpointConfigFromRow synAckPacket =
  case (synAckPacket ^. mptcpSendKey, synAckPacket ^. mptcpExpectedToken, synAckPacket ^. mptcpVersion) of 
    (Just key, Just token, Just version) -> Just $ MptcpEndpointConfiguration key token version
    _ -> Nothing
    -- error $ "Could not find key/token/version " ++ show synAckPacket

-- retreiveMptcpServerTokenFromRow :: Packet -> Maybe (Word64, Word32)
-- retreiveMptcpServerTokenFromRow synAckPacket = 
--   case (synAckPacket ^. mptcpSendKey, synAckPacket ^. mptcpExpectedToken) of 
--     (Just key, Just token) -> Just (key, token)
--     _ -> error "Could not generate"

-- TODO

buildMptcpConnectionFromStreamId :: FrameRec HostCols
    -> StreamId Mptcp -> Either String (FrameFiltered MptcpConnection Packet)
buildMptcpConnectionFromStreamId frame streamId' = do
    -- Right $ frameLength synPackets
    if frameLength streamPackets < 1 then
      Left $ "No packet with mptcp.stream == " ++ show streamId'
    else if frameLength synAckPackets < 1 then
      Left $ "No syn/ack packet found for stream" ++ show streamId' ++ " First packet: "
      -- ++ show streamPackets
    else if lefts subflows /= [] then
      Left $ concat (lefts subflows)
    else if mbServerConfig == Nothing then
      Left $ "Could not find MPTCP server config in " ++ show synAckPacket
    else

      case buildTcpConnectionFromStreamId streamPackets (synPacket ^. tcpStream) of
        Left err -> Left err
        Right aframe -> let
            clientFrame = filterFrame (\x -> ((not . isNothing) (x ^. mptcpSendKey))) aframe.ffFrame
            mbClientConfig = genMptcpEndpointConfigFromRow (frameRow clientFrame 0)
          in
            if frameLength clientFrame == 0 then
              Left $ "Could not find mptcp client key"
            else
              -- TODO now add a check on abstime
              -- if ds.loc[server_id, "abstime"] < ds.loc[client_id, "abstime"]:
              --     log.error("Clocks are not synchronized correctly")
              -- update temporary fframe with the computed subflows
              Right $ FrameTcp {
                    ffCon = tempMptcpConn mbClientConfig
                  , ffFrame = streamPackets
                }
    where
      streamPackets :: FrameRec HostCols
      streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId') frame
      --
      -- |Just for the time
      tempMptcpConn clientConfig = MptcpConnection {
            mpconStreamId = streamId'
          -- kinda risky, assumes we have the server key always
          , serverConfig = fromJust mbServerConfig
          , clientConfig = fromJust clientConfig
          -- , mptcpNegotiatedVersion = fromIntegral $ fromJust clientMptcpVersion :: Word8

          , subflows = Set.fromList $ map (.ffCon) (rights subflows)
        }
      -- suppose tcpflags is a list of flags, check if it is in the list
      -- of type FrameRec [(Symbol, *)]
      -- Looking for synack packets
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      synAckPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && TcpFlagAck `elem` (x ^. tcpFlags)) streamPackets

      synPacket = frameRow synPackets 0
      synAckPacket = frameRow synAckPackets 0
      mbServerConfig = genMptcpEndpointConfigFromRow synAckPacket

      -- masterTcpstreamId = synPacket ^. tcpStream
      -- clientMptcpVersion = synPacket ^. mptcpVersion

      --
      subflows = map (buildSubflowFromTcpStreamId frame) (getTcpStreams streamPackets)


-- filterFrame / buildFrameFromStreamId
{- Common interface to work with TCP and MPTCP connections
-}
class StreamConnection a where
  -- TODO add related wireshark fields ?
  type StreamType a :: Type
  type StreamFilter a :: Symbol
  showConnectionText :: a -> Text
  -- describeConnection :: a -> Text
  buildFrameFromStreamId :: Frame Packet -> StreamType a -> Either String (FrameFiltered a Packet)

  -- | Compare two conection and give a similarityScore
  similarityScore :: a -> a -> Int
  -- listConnections :: FrameFiltered () [a]
  -- summarize :: a -> Text


-- | Compares 2 TCP connections and gives a score
-- The higher the score, the more similar the 2 connections are.
scoreTcpCon :: TcpConnection -> TcpConnection -> Int
scoreTcpCon con1 con2 =
  -- If every parameter is equal, returns +oo else 0
  -- TODO also match on isn in case ports got reused

  foldl (\acc toAdd -> acc + 10 * fromEnum toAdd) (0 :: Int) [
      con1.clientIp   == con2.clientIp
    , con1.clientPort == con2.clientPort
    , con1.serverIp   == con2.serverIp
    , con1.serverPort == con2.serverPort
  ]


instance StreamConnection TcpConnection where
  type StreamType TcpConnection = StreamIdTcp
  type StreamFilter TcpConnection = "tcp.stream"
  showConnectionText = showTcpConnectionText
  buildFrameFromStreamId = buildTcpConnectionFromStreamId
  similarityScore = scoreTcpCon


-- | Computes a score
scoreMptcpCon :: MptcpConnection -> MptcpConnection -> Int
scoreMptcpCon con1 con2 =
  let keyScore = if con1.serverConfig.key == con2.serverConfig.key
                    && con1.clientConfig.key == con2.clientConfig.key
      then 200
      else 0
  in
    keyScore


instance StreamConnection MptcpConnection where
  type StreamType MptcpConnection = StreamIdMptcp
  type StreamFilter MptcpConnection = "mptcp.stream"
  showConnectionText = showMptcpConnectionText
  buildFrameFromStreamId = buildMptcpConnectionFromStreamId
  similarityScore = scoreMptcpCon

instance StreamConnection MptcpSubflow where
  type StreamType MptcpSubflow = StreamIdTcp
  type StreamFilter MptcpSubflow = "tcp.stream"
  showConnectionText = showMptcpSubflowText
  buildFrameFromStreamId = buildSubflowFromTcpStreamId
  -- TODO use score as well
  similarityScore sf1 sf2 = similarityScore sf1.connection  sf2.connection


-- |Show the subflow (ids)
showMptcpSubflowText :: MptcpSubflow -> Text
showMptcpSubflowText sf =
  showConnectionText sf.connection <> " (Local/Remote ids: " <> tshow sf.localId
      <> "/" <> tshow sf.remoteId <> ", token " <> tshow  sf.joinToken <> ")"

-- TODO add sthg in case it's the master subflow ?
showConnection :: StreamConnection a => a -> String
showConnection = T.unpack . showConnectionText
