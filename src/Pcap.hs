{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE FlexibleInstances                      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
module Pcap(PcapFrame, TsharkParams(..),
    defaultTsharkPrefs,
    defaultTsharkOptions
    )
where


import System.Process
import System.Exit
import Data.Vinyl
import Control.Lens hiding (Identity)
import Control.Lens.TH
import Data.Singletons.TH
import Frames.TH
import Frames

-- Inspired by http://hackage.haskell.org/package/vinyl-0.12.3/docs/Data-Vinyl-Tutorial-Overview.html
-- | DataType
data Fields = Name | Fullname | PlotLabel | Hash  deriving Show

-- , DataType
type TsharkField = [Name, Fullname, PlotLabel, Hash]

type family ElF (f :: Fields) :: * where
  ElF Name = String
  ElF Fullname = String
  ElF PlotLabel = String
  -- ElF DataType = Type
  ElF Hash = Bool
  -- ElF Master = Rec Attr LifeForm
newtype Attr f = Attr { _unAttr :: ElF f }
makeLenses ''Attr
-- TODO retablir les singletons  certainement
genSingletons [ ''Fields ]

instance Show (Attr Name) where show (Attr x) = "name: " ++ show x
instance Show (Attr Fullname) where show (Attr x) = "age: " ++ show x
instance Show (Attr PlotLabel) where show (Attr x) = "label: " ++ show x
instance Show (Attr Hash) where show (Attr x) = "hash: " ++ show x
-- instance Show (Attr Master) where show (Attr x) = "master: " ++ show x


-- TODO we should create a RowGen

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.
tableTypes "Packet" "data/server_2_filtered.pcapng.csv"
type PcapFrame = Frame Packet


-- tableTypes' (rowGen "data/server_2_filtered.pcapng.csv")
--             { rowTypeName = "NoH"
--             , columnNames = [ "Job", "Schooling", "Money", "Females"
--                             , "Respect", "Census", "Category" ]
--             , tablePrefix = "NoHead"}

-- TODO DateField / List
-- use higher kinded fields ?
-- data TsharkField t = Field {
--         fullname :: String
--         -- , type: Any  -- 
--         -- |How to reference it in plot
--         , label :: Maybe String
--         -- |Wether to take into account this field when creating a hash of a packet
--         , hash :: Bool
--         -- , converter :: a
--         -- converter: Optional[Callable]
--     } deriving (Read, Generic)

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
    RawCommand "tshark" (start ++ opts ++ readFilter ++ fields)
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        start = [
              tsharkBinary tsharkParams,
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
            foldr (\fname l -> l ++ ["-e", fname]) [] fieldNames
            )


-- derive from Order ?
-- define as a set ?
defaultTsharkOptions :: [(String, String)]
defaultTsharkOptions = [
      -- TODO join these
      ("gui.column.format", concat [ "Time","%At","ipsrc","%s","ipdst","%d"]),
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

defaultTsharkPrefs = TsharkParams {
      tsharkBinary = "tshark",
      tsharkOptions = defaultTsharkOptions,
      csvDelimiter = '|',
      tsharkReadFilter = Nothing
    }

-- :->
-- baseFields :: [TsharkField]
-- baseFields = [
    -- 'UInt64'
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
    -- ]

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

