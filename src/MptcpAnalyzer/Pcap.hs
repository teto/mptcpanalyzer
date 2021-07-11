{-# LANGUAGE ConstraintKinds        #-}
{-# LANGUAGE DataKinds              #-}
{-# LANGUAGE DeriveGeneric          #-}
{-# LANGUAGE EmptyCase              #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs                  #-}
{-# LANGUAGE KindSignatures         #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE PatternSynonyms        #-}
{-# LANGUAGE PolyKinds              #-}
{-# LANGUAGE QuasiQuotes            #-}
{-# LANGUAGE ScopedTypeVariables    #-}
{-# LANGUAGE TemplateHaskell        #-}
{-# LANGUAGE TypeApplications       #-}
{-# LANGUAGE TypeFamilies           #-}
{-# LANGUAGE TypeOperators          #-}
{-# LANGUAGE UndecidableInstances   #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE PackageImports         #-}
module MptcpAnalyzer.Pcap
-- (TsharkParams(..),
--     defaultTsharkPrefs
--     , defaultTsharkOptions
--     , generateCsvCommand
--     , exportToCsv
--     , loadRows
--     , getTcpStreams
--     )
where


import           MptcpAnalyzer.ArtificialFields
import           MptcpAnalyzer.Stream
import           MptcpAnalyzer.Types
import           Net.Mptcp
import           Net.Tcp
import           "mptcp-pm" Net.Tcp             (TcpFlag (..))
import           Tshark.Fields
import           Tshark.TH

import           Data.Monoid                    (First (..))
import qualified Data.Text                      as T
import qualified Data.Text.IO                   as T
import qualified Data.Vector                    as V
import           Frames
import           Frames.TH
import           System.Exit
import           System.IO                      (BufferMode (LineBuffering), Handle, SeekMode (AbsoluteSeek),
                                                 hGetContents, hSeek, hSetBuffering)
import           System.Process
-- import Frames.InCore
import           Frames.CSV                     (ParserOptions (..), QuotingMode (..), ReadRec, pipeTableEitherOpt,
                                                 produceTextLines, readFileLatin1Ln, readTableMaybeOpt)
import           Frames.Col
import           Frames.ColumnTypeable          (Parseable (..), Parsed (..), parseIntish)
import           Frames.ShowCSV
-- for Record
-- import Frames.Rec (Record(..))
import           Data.List                      (intercalate)
import           Net.IP
-- for symbol
-- import GHC.Types
import qualified Control.Foldl                  as L
import qualified Data.Set                       as Set
-- import Language.Haskell.TH
-- import Language.Haskell.TH.Syntax
-- import Lens.Micro
-- import Lens.Micro.Extras
import           Control.Lens
import qualified Data.Foldable                  as F
import           Data.Maybe                     (catMaybes, fromJust)
import           Data.Vinyl                     (ElField (..), Rec (..), rapply, rmapX, xrec)
import           Data.Vinyl.Class.Method
import           Data.Vinyl.Functor             (Compose (..), (:.))
import           Data.Word                      (Word16, Word32, Word64, Word8)
import           GHC.Base                       (Symbol)
import           GHC.List                       (foldl')
import           GHC.TypeLits                   (KnownSymbol)
import           Numeric                        (readHex)
import           Pipes                          (Producer, cat, (>->))
import qualified Pipes.Prelude                  as P
-- import qualified Frames.InCore
import           Data.Either                    (lefts, rights)
import qualified Data.Map                       as Map
import           Debug.Trace
import qualified Frames.InCore                  as I


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

-- |
data TsharkParams = TsharkParams {
      tsharkBinary     :: String,
      -- |(Name, Value) of tshark options, see 'defaultTsharkOptions'
      tsharkOptions    :: [(String, String)],
      -- |
      csvDelimiter     :: Char,
      tsharkReadFilter :: Maybe String
    }

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

-- |Generate the tshark command to export a pcap into a csv
generateCsvCommand :: [T.Text] -- ^Fields to exports e.g., "mptcp.stream"
          -> FilePath    -- ^ path towards the pcap file
          -> TsharkParams
          -> CmdSpec
generateCsvCommand fieldNames pcapFilename tsharkParams =
    RawCommand (tsharkBinary tsharkParams) args
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        start = [
            "-r", pcapFilename,
            "-E", "separator=" ++ [csvDelimiter tsharkParams]
          ]

        args :: [String]
        args = (start ++ opts ++ readFilter ) ++ map T.unpack  fields

        opts :: [String]
        opts = foldr (\(opt, val) l -> l ++ ["-o", opt ++ ":" ++ val]) [] (tsharkOptions tsharkParams)

        readFilter :: [String]
        readFilter = case tsharkReadFilter tsharkParams of
            Just x  ->["-2", "-R", x]
            Nothing -> []

        fields :: [T.Text]
        fields = ["-T", "fields"]
            ++ Prelude.foldr (\fieldName l -> ["-e", fieldName] ++ l) [] fieldNames



-- TODO pass a list of options too
-- TODO need to override 'WIRESHARK_CONFIG_DIR' = tempfile.gettempdir()
-- (MonadIO m, KatipContext m) =>
{- Export to CSV

-}
exportToCsv ::
  -- Members ()
  TsharkParams
  -> FilePath  -- ^Path to the pcap
  -> FilePath -- ^ temporary file
  -> Handle -- ^ temporary file
-- ^See haskell:readCreateProcessWithExitCode
  -> IO (FilePath, ExitCode, String)
exportToCsv params pcapPath path tmpFileHandle = do
    let
        (RawCommand bin args) = generateCsvCommand fields pcapPath params
        createProc :: CreateProcess
        createProc = (proc bin args) {
            std_err = CreatePipe,
            std_out = UseHandle tmpFileHandle
            }
    putStrLn $ "Exporting fields " ++ show fields
    putStrLn $ "Command run: " ++ show (RawCommand bin args)
    -- TODO write header
    -- TODO redirect stdout towards the out handle
    hSetBuffering tmpFileHandle LineBuffering
    hSeek tmpFileHandle AbsoluteSeek 0 >> T.hPutStrLn tmpFileHandle fieldHeader
    (_, _, Just herr, ph) <-  createProcess_ "error" createProc
    exitCode <- waitForProcess ph
    -- TODO do it only in case of error ?
    err <- hGetContents herr
    return (path, exitCode, err)
    where
      fields :: [T.Text]
      fields = Map.elems $ Map.map tfieldFullname baseFields

      csvSeparator = T.pack [csvDelimiter params]
      fieldHeader :: Text
      fieldHeader = T.intercalate csvSeparator (Map.keys baseFields)

-- "data/server_2_filtered.pcapng.csv"
-- la le probleme c'est que je ne passe pas d'options sur les separators etc
-- ca foire silencieusement ??
-- maybe use a readTableMaybe instead
-- readTable path

loadRows :: (I.RecVec a, ReadRec a) => FilePath -> IO (FrameRec a)
loadRows path = inCoreAoS (
  eitherProcessed path
  )



type ManEither = Rec (Either T.Text :. ElField) (RecordColumns Packet)

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

-- http://acowley.github.io/Frames/#orgf328b25
defaultTsharkOptions :: [(String, String)]
defaultTsharkOptions = [
      -- TODO join these
      ("gui.column.format", intercalate "," [ "Time","%At","ipsrc","%s","ipdst","%d"]),
      -- "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
      ("tcp.analyze_sequence_numbers", "true"),
      ("mptcp.analyze_mappings", "true"),
      ("mptcp.relative_sequence_numbers", "true"),
      ("mptcp.intersubflows_retransmission", "true"),
      -- # Disable DSS checks which consume quite a lot
      ("mptcp.analyze_mptcp", "true")
      ]

-- data TsharkPrefs = TsharkPrefs {
--     analyzeTcpSeq :: Bool
--     , analyzeMptcp :: Bool
--     , mptcpRelSeq :: Bool
--     , analyzeMptcp :: Bool
--   } deriving Show

defaultTsharkPrefs :: TsharkParams
defaultTsharkPrefs = TsharkParams {
      tsharkBinary = "tshark",
      tsharkOptions = defaultTsharkOptions,
      csvDelimiter = '|',
      tsharkReadFilter = Just "mptcp or tcp and not icmp"
    }


{-
-}
getTcpFrame :: FrameRec HostCols -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
getTcpFrame = buildTcpConnectionFromStreamId

-- | For now assume the packet is the first syn from client to server
buildTcpConnectionFromRecord :: (
  IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
    -- rs ⊆ HostCols

  )
  => Record rs -> TcpConnection
buildTcpConnectionFromRecord r =
  TcpConnection {
    conTcpClientIp = r ^. ipSource
    , conTcpServerIp = r ^. ipDest
    , conTcpClientPort = r ^. tcpSrcPort
    , conTcpServerPort = r ^. tcpDestPort
    , conTcpStreamId = r ^. tcpStream
  }

{- Builds a Tcp connection from a non filtered frame
-}
buildTcpConnectionFromStreamId ::
  FrameRec HostCols
  -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
buildTcpConnectionFromStreamId frame streamId =
    if frameLength synPackets < 1 then
      Left $ "No packet with any SYN flag for tcp.stream " ++ show streamId
    else
      -- TODO check who is client
      Right $ FrameTcp (buildTcpConnectionFromRecord $ frameRow synPackets 0) streamPackets
    where
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets

-- | Builds
-- should expect a filteredFrame with MPTCP
-- buildSubflowFromTcpStreamId :: FrameFiltered TcpConnection Packet -> StreamId Tcp -> Either String (FrameFiltered MptcpSubflow Packet)
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
buildSubflowFromTcpStreamId frame streamId =
    if frameLength synPackets < 1 then
      Left $ "No packet with any SYN flag for tcp.stream " ++ show streamId
    else
      -- TODO check who is client
      Right $ FrameTcp sf streamPackets
    where
      syn0 = frameRow synPackets 0
      streamPackets = filterFrame  (\x -> x ^. tcpStream == streamId) frame
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      sfCon = buildTcpConnectionFromRecord syn0
      -- rcvToken
      sf = MptcpSubflow {
        sfConn = sfCon
        -- TODO ignore if it's master token
        , sfJoinToken = syn0 ^. mptcpRecvToken
        , sfPriority = Nothing
        , sfLocalId = 0
        , sfRemoteId = 0
        , sfInterface = "unknown"
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
      -- filteredFrame = filterFrame  (\x -> x ^. mptcpStream == Just (mptcpStreamId con)) frame
      -- filteredFrame = filterFrame  (\x -> (rgetField @MptcpStream x) == Just (mptcpStreamId con)) frame

      subflowFrames = map addDestsToSubflowFrames subflows

      addDestsToSubflowFrames sf = addMptcpDestToFrame (addTcpDestToFrame frame (sfConn sf)) sf

      addMptcpDest' role x = (Col role) :& x

      addMptcpDestToFrame frame' sf = fmap (addMptcpDest' (getMptcpDest con sf)) frame'

      startingFrame = fmap setTempDests frame
      setTempDests :: Record rs -> Record ( MptcpDest ': TcpDest ': rs)
      setTempDests x = Col RoleClient :& (Col RoleClient) :& x
      addMptcpDestToRec x role = (Col $ role) :& x
      subflows = Set.toList $ mpconSubflows con

addMptcpDestToFrame :: MptcpConnection -> FrameFiltered MptcpSubflow Packet -> FrameRec ('[MptcpDest])
addMptcpDestToFrame mpcon (FrameTcp sf frame) = fmap (addMptcpDest' (getMptcpDest mpcon sf)) frame
  where
      addMptcpDest' role x = (Col role) :& RNil


getMptcpDest :: MptcpConnection -> MptcpSubflow -> ConnectionRole
getMptcpDest mptcpCon sf = case sfJoinToken sf of
  -- master subflow, dest is by definition the server
  Nothing -> RoleServer
  Just token -> if token == mptcpServerToken mptcpCon then
    RoleServer
  else
    RoleClient


-- | Sets TCP role column
-- append a column with a value role
-- Todo accept a 'FrameFiltered'
-- I want to check it is included
addTcpDestToFrame :: (
  I.RecVec rs
  ,IpSource ∈ rs, IpDest ∈ rs
  , IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs
  , TcpStream ∈ rs
  )
    => FrameRec rs
    -> TcpConnection
    -> FrameRec ( TcpDest ': rs )
addTcpDestToFrame frame con = fmap (\x -> addTcpDestToRec x (computeTcpDest x con)) streamFrame
    where
      streamFrame = filterFrame  (\x -> rgetField @TcpStream x == conTcpStreamId con) frame


-- | Generates a frame with the TcpDest
genTcpDestFrame :: (
  I.RecVec rs
  ,IpSource ∈ rs, IpDest ∈ rs
  , IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs
  , TcpStream ∈ rs
  )
    => FrameRec rs
    -> TcpConnection
    -> FrameRec '[TcpDest]
genTcpDestFrame frame con = fmap (\x -> Col (computeTcpDest x con) :& RNil) streamFrame
    where
      streamFrame = filterFrame  (\x -> rgetField @TcpStream x == conTcpStreamId con) frame

-- TODO addTcpDestToFrame

computeTcpDest :: (
  TcpStream ∈ rs
  , IpSource ∈ rs
  , IpDest ∈ rs
  , TcpSrcPort ∈ rs
  , TcpDestPort ∈ rs
  ) => Record rs
  -> TcpConnection -> ConnectionRole
computeTcpDest x con  = if (rgetField @IpSource x) == conTcpClientIp con
                && rgetField @IpDest x == conTcpServerIp con
                && rgetField @TcpSrcPort x == conTcpClientPort con
                && rgetField @TcpDestPort x == conTcpServerPort con
                && rgetField @TcpDestPort x == conTcpServerPort con
                -- TODO should error if not the same streamId
                -- && (rgetField @TcpStream x) == (conTcpStreamId con)
        then RoleServer else RoleClient


-- | TODO
-- See @addTcpDestToFrame@
addTcpDestinationsToAFrame :: (
  -- HostCols ⊆ rs,
  I.RecVec rs
  -- , HostCols <: rs
  -- , HostCols ∈ rs
  , IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs

  )
  => FrameFiltered TcpConnection (Record rs)
  -> FrameFiltered TcpConnection (Record (TcpDest ': rs))
addTcpDestinationsToAFrame aframe =
  aframe { ffFrame = addDestinationsToFrame' (ffCon aframe)}
  where
    frame = ffFrame aframe
    addDestinationsToFrame' con = addTcpDestToFrame frame con

-- append a field with a value role
addTcpDestToRec :: (TcpStream ∈ rs, IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs)
  => Record rs -> ConnectionRole ->  Record  ( TcpDest ': rs )
addTcpDestToRec x role = (Col $ role) :& x



buildMptcpConnectionFromStreamId ::
    FrameRec HostCols
    -> StreamId Mptcp -> Either String (FrameFiltered MptcpConnection Packet)
buildMptcpConnectionFromStreamId frame streamId = do
    -- Right $ frameLength synPackets
    if frameLength streamPackets < 1 then
      Left $ "No packet with mptcp.stream == " ++ show streamId
    else if frameLength synAckPackets < 1 then
      Left $ "No syn/ack packet found for stream" ++ show streamId ++ " First packet: "
      -- ++ show streamPackets
    else if lefts subflows /= [] then
      Left $ concat (lefts subflows)
    else
      -- TODO now add a check on abstime
      -- if ds.loc[server_id, "abstime"] < ds.loc[client_id, "abstime"]:
      --     log.error("Clocks are not synchronized correctly")
      -- update temporary fframe with the computed subflows
      Right tempFframe
      -- {
      --     ffCon = (ffCon tempFframe) {
      --         mpconSubflows = Set.fromList $ map ffCon (rights subflows)
      --     }
      -- }
      --  $ frameRow synPackets 0
    where
      streamPackets :: FrameRec HostCols
      streamPackets = filterFrame  (\x -> x ^. mptcpStream == Just streamId) frame
      --
      tempFframe = FrameTcp {
          ffCon = tempMptcpConn
        , ffFrame = streamPackets
      }
      -- |Just for the time
      tempMptcpConn = MptcpConnection {
          mptcpStreamId = streamId
          , mptcpServerKey = fromJust $ synAckPacket ^. mptcpSendKey
          , mptcpClientKey = fromJust $ synPacket ^. mptcpSendKey
          , mptcpServerToken = fromJust $ synAckPacket ^. mptcpExpectedToken
          , mptcpClientToken = fromJust $ synPacket ^. mptcpExpectedToken
          , mptcpNegotiatedVersion = fromIntegral $ fromJust clientMptcpVersion :: Word8

          , mpconSubflows = Set.fromList $ map ffCon (rights subflows)
        }
      -- suppose tcpflags is a list of flags, check if it is in the list
      -- of type FrameRec [(Symbol, *)]
      -- Looking for synack packets
      synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      synAckPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && TcpFlagAck `elem` (x ^. tcpFlags)) streamPackets

      synPacket = frameRow synPackets 0
      synAckPacket = frameRow synAckPackets 0

      masterTcpstreamId = synPacket ^. tcpStream

      clientMptcpVersion = synPacket ^. mptcpVersion

      --
      subflows = map (buildSubflowFromTcpStreamId frame) (getTcpStreams streamPackets)


-- filterFrame / buildFrameFromStreamId
{- Common interface to work with TCP and MPTCP connections
-}
class StreamConnection a b | a -> b where
  -- | How
  showConnectionText :: a -> Text
  -- describeConnection :: a -> Text
  buildFrameFromStreamId :: Frame Packet -> StreamId b -> Either String (FrameFiltered a Packet)

  -- type toto = Int

  -- | Compare two conection and give a similarityScore
  similarityScore :: a -> a -> Int
  -- listConnections :: FrameFiltered () [a]
  -- summarize :: a -> Text
  -- GetLabel ?


-- | Compares 2 TCP connections and gives a score
-- The higher the score, the more similar the 2 connections are.
scoreTcpCon :: TcpConnection -> TcpConnection -> Int
scoreTcpCon con1 con2 =
  -- If every parameter is equal, returns +oo else 0
  -- TODO also match on isn in case ports got reused

  foldl (\acc toAdd -> acc + 10 * fromEnum toAdd) (0 :: Int) [
    conTcpClientIp con1 == conTcpClientIp con2
    , conTcpClientPort con1 == conTcpClientPort con2
    , conTcpServerIp con1 == conTcpServerIp con2
    , conTcpServerPort con1 == conTcpServerPort con2
  ]


instance StreamConnection TcpConnection Tcp where
  showConnectionText = showTcpConnectionText
  buildFrameFromStreamId = buildTcpConnectionFromStreamId
  similarityScore = scoreTcpCon


-- | Computes a score
scoreMptcpCon :: MptcpConnection -> MptcpConnection -> Int
scoreMptcpCon con1 con2 =
  let keyScore = if mptcpServerKey con1 == mptcpServerKey con2 && mptcpClientKey con1 == mptcpClientKey con2
      then
          200
      else
          0
  in
    keyScore


instance StreamConnection MptcpConnection Mptcp where
  showConnectionText = showMptcpConnectionText
  buildFrameFromStreamId = buildMptcpConnectionFromStreamId
  similarityScore = scoreMptcpCon

instance StreamConnection MptcpSubflow Tcp where
  showConnectionText = showMptcpSubflowText
  buildFrameFromStreamId = buildSubflowFromTcpStreamId
  -- TODO use score as well
  similarityScore sf1 sf2 = similarityScore (sfConn sf1) (sfConn sf2)


-- |Show the subflow (ids)
showMptcpSubflowText :: MptcpSubflow -> Text
showMptcpSubflowText sf =
  showConnectionText (sfConn sf) <> " (Local/Remote ids: " <> tshow (sfLocalId sf)
      <> "/" <> tshow (sfRemoteId sf) <> ", token " <> tshow (sfJoinToken sf) <> ")"

-- TODO add sthg in case it's the master subflow ?
showConnection :: StreamConnection a b => a -> String
showConnection = T.unpack . showConnectionText
