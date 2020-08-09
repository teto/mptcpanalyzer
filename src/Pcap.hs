{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleContexts, QuasiQuotes #-}
module Pcap(PcapFrame, TsharkParams(..),
    defaultTsharkPrefs
    , defaultTsharkOptions
    , generateCsvCommand
    , exportToCsv
    , loadRows
    , getTcpStream
    )
where


-- import Frames.InCore (VectorFor)
import Net.IP
import System.IO (Handle, hGetContents)
import System.Process
import System.Exit
-- import Katip
import Data.Vinyl ()
-- import Control.Lens hiding (Identity)
-- import Control.Lens.TH
-- import Data.Word
-- import Pipes hiding (Proxy)
-- import qualified Pipes.Prelude as P
import Frames.TH
import Frames
-- import Frames.CSV
-- import Columns
-- for Record
-- import Frames.Rec (Record(..))
-- import Frames.ColumnTypeable
import Data.List (intercalate)
-- for symbol
-- import GHC.Types
import qualified Control.Foldl as L

-- import Lens.Micro
-- import Lens.Micro.Extras
import Control.Lens
-- import qualified Data.Vector as V

-- Inspired by http://hackage.haskell.org/package/vinyl-0.12.3/docs/Data-Vinyl-Tutorial-Overview.html
-- | DataType
    -- SFullName "frame.number" :& (SName "packetid") :&  False False
    -- Field "frame.interface_name" "interface" 'category' False False,
    -- Field "_ws.col.ipsrc"  "ipsrc" str False False,
    -- Field "_ws.col.ipdst" "ipdst" str False False,
    -- Field "ip.src_host" "ipsrc_host" str False False,
    -- Field "ip.dst_host" "ipdst_host" str False False,
    -- Field "tcp.stream" "tcpstream" 'UInt64' False False,
    -- Field "tcp.srcport" "sport" 'UInt16' False False,
    -- Field "tcp.dstport" "dport" 'UInt16' False False,
    -- Field "tcp.dstport" "dport" 'UInt16' False False,
    -- Field "frame.time_relative" "reltime" str "Relative time" False False
    -- Field "frame.time_epoch" "abstime" str "seconds+Nanoseconds time since epoch" False False

-- data TsharkField = FrameInterface | IpSource | IpDestination | TcpStream | TcpSrcPort | TcpDestPort deriving Show


-- instance Parseable TsharkField where
--   representableAsType
-- parse :: MonadPlus m => Text -> m (Parsed a) 
    -- parse text = return $ Definitely

-- , DataType
-- type TsharkFieldRow = ['FrameInterface, 'IpSource, 'IpDestination, 'TcpStream, 'TcpSrcPort, 'TcpDestPort]

-- type family ElF (f :: TsharkField) :: * where
--   ElF FrameInterface = Int
--   ElF IpSource = String
--   ElF IpDestination = String
--   ElF TcpStream = Word32
--   ElF TcpSrcPort = Word16
--   ElF TcpDestPort = Word16
--   -- ElF DataType = Type
--   -- ElF 'Hash = Bool
--   -- ElF Master = Rec Attr LifeForm


-- newtype Attr f = Attr { _unAttr :: ElF f }
-- makeLenses ''Attr
-- -- TODO retablir les singletons  certainement
-- genSingletons [ ''TsharkField ]

-- instance Show (Attr 'FrameInterface) where show (Attr x) = "FrameInterface: " ++ show x
-- instance Show (Attr 'IpSource) where show (Attr x) = "ip source: " ++ show x
-- instance Show (Attr 'IpDestination) where show (Attr x) = "ipDest: " ++ show x
-- instance Show (Attr 'TcpStream) where show (Attr x) = "tcpStream: " ++ show x
-- instance Show (Attr 'TcpSrcPort) where show (Attr x) = "tcpSrcPort: " ++ show x
-- instance Show (Attr 'TcpDestPort) where show (Attr x) = "destport: " ++ show x


-- TODO we should create a RowGen

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.
-- tableTypes "Packet" "data/server_2_filtered.pcapng.csv"
-- type PcapFrame = Frame Packet

-- simpleRecord :: 
-- alias of Rec ElField
-- RecordColumns
-- &:
-- toNamedField
-- , "mptcpstream" :->

-- or Packet
-- ElF FrameInterface
-- type TcpStreamT = "tcpstream" :-> Word32

-- Word32
-- type Packet = Record '[ "tcpstream" :-> Int ]

-- type (:->) (a :: Symbol) b = '(a, b)
-- type Age = "age" :-> Int

-- RecordColumns (Record ts) = ts
-- A Frame whose rows are Record values.
-- type FrameRec rs = Frame (Record rs)
-- type PcapFrame = Frame SimpleRecord
  -- type FrameMerged = FrameRec

-- TODO support TcpFlags / IPAddress and list of XXX
type MyColumns = IP ': CommonColumns

-- this declares Tcpstream = "tcpstrean" :-> Int for instance
tableTypes' (rowGen "data/simple.csv" )
            { rowTypeName = "Packet"
            , separator = "|"
            -- pass specific columns such as tcpflags, lists, ipsrc
            -- , columnUniverse
            -- , columnUniverse = $(colQ ''MyColumns)
            , columnNames = ["tcpstream", "tcpflags", "ipsrc"]
            -- , tablePrefix = "NoHead"
            }

type PcapFrame = Frame Packet

-- TODO DateField / List
-- use higher kinded fields ?
data TsharkFieldDesc = TsharkFieldDesc {
        fullname :: String
        -- ^Test
        -- , colType :: Symbol
        -- , colType :: TsharkField
        -- ^How to reference it in plot
        , label :: Maybe String
        -- ^Wether to take into account this field when creating a hash of a packet
        , hash :: Bool
    }
    -- deriving (Read, Generic)

data TsharkParams = TsharkParams {
      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      tsharkReadFilter :: Maybe String
    }

-- |Generate the tshark command to export a pcap into a csv
generateCsvCommand :: [String] -- ^Fields to exports e.g., "mptcp.stream"
          -> FilePath    -- ^ path towards the pcap file
          -> TsharkParams
          -> CmdSpec
generateCsvCommand fieldNames pcapFilename tsharkParams =
    RawCommand (tsharkBinary tsharkParams) (start ++ opts ++ readFilter ++ fields)
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        start = [
              "-r", pcapFilename,
              "-E", "separator=" ++ show (csvDelimiter tsharkParams)
            ]
        -- if self.profile:
        --     cmd.extend(['-C', self.profile])

        opts :: [String]
        opts = foldr (\(opt, val) l -> l ++ ["-o", opt ++ ":" ++ val]) [] (tsharkOptions tsharkParams)

        readFilter :: [String]
        readFilter = case tsharkReadFilter tsharkParams of
            Just x ->["-2", "-R", x]
            Nothing -> []

        fields :: [String]
        fields = ["-T", "fields"] ++ (
            Prelude.foldr (\fname l -> l ++ ["-e", fname]) [] fieldNames
            )

-- TODO pass a list of options too
-- (MonadIO m, KatipContext m) =>
exportToCsv ::  TsharkParams ->
                FilePath  -- ^Path to the pcap
                -> FilePath -> Handle -- ^ temporary file
              -- ^See haskell:readCreateProcessWithExitCode
                -> IO (FilePath, ExitCode, String)
exportToCsv params pcapPath path fd = do
    -- custom_env['WIRESHARK_CONFIG_DIR'] = tempfile.gettempdir()
    --
    let
        (RawCommand bin args) = generateCsvCommand fields pcapPath params
        createProc :: CreateProcess
        createProc = (proc bin args) {
            std_err = CreatePipe,
            std_out = UseHandle fd
            }
    -- TODO write header
    -- withCreateProcess (proc cmd args) { ... }  $ \stdin stdout stderr ph -> do
    -- runInteractiveProcess
    -- TODO redirect stdout towards the out handle
    -- TODO use createProcess instead
    -- readCreateProcessWithExitCode ignores std_out/std_err
    -- IO (Maybe Handle, Maybe Handle, Maybe Handle, ProcessHandle)
    (_, _, Just herr, ph) <-  createProcess_ "error" createProc
    exitCode <- waitForProcess ph
    -- TODO do it only in case of error ?
    err <- hGetContents herr
    -- TODO retrun stderr
    return (path, exitCode, err)
    -- return $ (path, res)
    -- liftIO $ callProcess bin args
    -- if exitCode == 0 then
    --   putCache cacheId
    -- else
    where
      fields :: [String]
      fields = [
        "tcp.stream"
        ]

-- custom data
-- data PcapCustom = PcapCustom {
--     }

-- No instance for (Vector (VectorFor Word32) Word32

-- No instance for (Parseable Word32)
-- "data/server_2_filtered.pcapng.csv"
loadRows :: FilePath -> IO (PcapFrame)
loadRows path = inCoreAoS (
    readTable path
    )

-- http://acowley.github.io/Frames/#orgf328b25
-- movieStream :: MonadSafe m => Producer User m ()
-- movieStream = readTableOpt userParser "data/ml-100k/u.user"

-- derive from Order ?
-- define as a set ?
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

-- :->
-- baseFields :: [(Symbol, TsharkFieldDesc)]
-- baseFields = [
--     -- 'UInt64'
--     -- SFullName "frame.number" :& (SName "packetid") :&  False False
--     -- " "interface"
--     ("packetid", TsharkFieldDesc "frame.interface_name"  FrameInterface Nothing False),
--     ("ipsrc", TsharkFieldDesc "_ws.col.ipsrc" IpSource (Just "source ip") False),
--     ("ipdst", TsharkFieldDesc "_ws.col.ipdst" IpDestination Nothing False)
--     -- Field "ip.src_host" "ipsrc_host" str False False,
--     -- Field "ip.dst_host" "ipdst_host" str False False,
--     -- Field "tcp.stream" "tcpstream" 'UInt64' False False,
--     -- Field "tcp.srcport" "sport" 'UInt16' False False,
--     -- Field "tcp.dstport" "dport" 'UInt16' False False,
--     -- Field "tcp.dstport" "dport" 'UInt16' False False,
--     -- Field "frame.time_relative" "reltime" str "Relative time" False False
--     -- Field "frame.time_epoch" "abstime" str "seconds+Nanoseconds time since epoch" False False
--     ]

-- packetParser :: ParserOptions
-- packetParser = ParserOptions (Just (map T.pack ["tcpstream"
--                                              -- , "age"
--                                              -- , "gender"
--                                              -- , "occupation"
--                                              -- , "zip code"
--                               ]))
--                            (T.pack "|")
--                            (Frames.CSV.RFC4180Quoting '"')
-- packetStream :: MonadSafe m => Producer SimpleRecord m ()
-- packetStream = readTableOpt packetParser "data/ml-100k/u.user"

-- F.Foldl 
-- ps = packet stream
-- nub :: Ord a => Fold a [a]
-- Fold a b
getTcpStream :: PcapFrame -> [Int]
getTcpStream ps =
    L.fold L.nub (view tcpstream <$> ps)

-- mptcpFields :: [TsharkField]
-- mptcpFields = [
--         -- # TODO use 'category'
--         -- # rawvalue is tcp.window_size_value
--         -- # tcp.window_size takes into account scaling factor !
--         Field "tcp.window_size" "rwnd" 'Int64' True True
--         Field "tcp.flags" "tcpflags" 'UInt8' False True _convert_flags
--         Field "tcp.option_kind" "tcpoptions" None False False
--             -- functools.partial(_load_list field="option_kind") )
--         Field "tcp.seq" "tcpseq" 'UInt32' "TCP sequence number" True
--         Field "tcp.len" "tcplen" 'UInt16' "TCP segment length" True
--         Field "tcp.ack" "tcpack" 'UInt32' "TCP segment acknowledgment" True
--         Field "tcp.options.timestamp.tsval" "tcptsval" 'Int64'
--             "TCP timestamp tsval" True
--         Field "tcp.options.timestamp.tsecr" "tcptsecr" 'Int64'
--             "TCP timestamp tsecr" True
--     ]


-- loadCsv :: Filepath ->

-- runTshark ::
-- runTshark = 
    -- (exitCode, stdout, stderrContent) <- readProcessWithExitCode program [filename, show subflowCount] ""


-- tsharkPrefsToString :: TsharkPrefs -> String
-- tsharkPrefsToString = 

