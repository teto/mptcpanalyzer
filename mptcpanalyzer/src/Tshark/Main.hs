{-|
Module      : Tshark.Profile
Description : Interface between wireshark output format and haskell
Maintainer  : matt


WIRESHARK_CONFIG_DIR'

-}
module Tshark.Main (
  TsharkParams(csvDelimiter, tsharkReadFilter)
  , generateCsvCommand
  , defaultTsharkPrefs
  , defaultTsharkOptions
  , genReadFilterFromTcpConnection
)
where

import qualified Data.Text as T
import System.Process
import           Data.List                      (intercalate)
import Net.Tcp (TcpConnection(..))
import MptcpAnalyzer.ArtificialFields (ConnectionRole)
import qualified Net.IP

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


defaultTsharkPrefs :: TsharkParams
defaultTsharkPrefs = TsharkParams {
      tsharkBinary = "tshark",
      tsharkOptions = defaultTsharkOptions
      , csvDelimiter = '|'
      , tsharkReadFilter = Just "mptcp or tcp and not icmp"
      , tsharkProfile = Nothing
    }

showIP :: Net.IP.IP -> String
showIP = T.unpack . Net.IP.encode

-- |Create a tshark read filter from a 'TcpConnection'
genReadFilterFromTcpConnection ::
  TcpConnection
  -> Maybe ConnectionRole   -- ^If we care about direction (ignored for now)
  -> String
genReadFilterFromTcpConnection con dest =
  case dest of
    Just x -> error "not implemented"
      -- TODO should depend on destination
      -- "ip.src==" ++ (show . conTcpClientIp) con ++ "ip.dst==" ++ (show . conTcpServerIp) con
      --   ++ " tcp.srcport==" ++ show (conTcpSou con) ++ " and tcp.dstport==" ++ show (conTcpClientPort con)

        -- error "not implemented"
    _ -> "tcp and ip.addr==" ++ (showIP . conTcpClientIp) con ++ " and ip.addr==" ++ (showIP . conTcpServerIp) con 
        ++ " tcp.port==" ++ show (conTcpServerPort con) ++ " and tcp.port==" ++ show (conTcpClientPort con)

-- |Create a tshark read filter from a 'MptcpConnection'
-- genReadFilterFromMptcpConnection :: MptcpConnection -> String
-- genReadFilterFromMptcpConnection con =



-- | Basic wireshark settings to enforce reproducible results across users
data TsharkParams = TsharkParams {
      tsharkBinary     :: String,
      -- |(Name, Value) of tshark options, see 'defaultTsharkOptions'
      tsharkOptions    :: [(String, String)],
      -- | Flags to add on the command line
      -- tsharkFlags     :: [String],
      -- | How to separate the different fields
      csvDelimiter     :: Char
      -- | for instance "mptcp" or "tcp"
      , tsharkReadFilter :: Maybe String

      -- | Path towards the tshark profile to use (passed as `tshark -C ...`)
      , tsharkProfile :: Maybe FilePath
    }


-- split into live ?
-- inspired by TcpConnection
-- data TsharkFilter =  TsharkFilter {
--   tfTcpClientIp :: IP -- ^Client ip
--   , tfTcpServerIp :: IP -- ^Server ip
--   , tfTcpClientPort :: Word16  -- ^ Source port
--   , tfTcpServerPort :: Word16  -- ^Destination port
--   -- tfProto :: 
--   -- tfStreamId :: 
-- }


-- |Generate the tshark command to export a pcap into a csv
generateCsvCommand :: [T.Text] -- ^Fields to exports e.g., "mptcp.stream"
          -> Either String FilePath    -- ^ (interface, path towards the pcap file)
          -> TsharkParams
          -> CmdSpec
generateCsvCommand fieldNames source tsharkParams =
    RawCommand (tsharkBinary tsharkParams ) args
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        start = [
            "-E", "separator=" ++ [csvDelimiter tsharkParams]
          ] ++ (case source of
              Right pcapFilename -> ["-r", pcapFilename]
              Left ifname  -> ["-i", ifname])


        args :: [String]
        args = (start ++ opts ++ readFilter ) ++ map T.unpack  fields

        opts :: [String]
        opts = foldr (\(opt, val) l -> l ++ ["-o", opt ++ ":" ++ val]) [] (tsharkOptions tsharkParams)

        readFilter :: [String]
        readFilter = case tsharkReadFilter tsharkParams of
            Just x  -> (case source of
              Right pcapFilename -> ["-2", "-R"]
              Left ifname  -> ["-Y"]) ++ [x]
            Nothing -> []

        fields :: [T.Text]
        fields = ["-T", "fields"]
            ++ Prelude.foldr (\fieldName l -> ["-e", fieldName] ++ l) [] fieldNames
