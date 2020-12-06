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
    , getTcpStreams
    )
where


-- import Frames.InCore (VectorFor)
import qualified Data.Text as T
import Tshark.TH
-- import Net.IP
import System.IO (Handle, hGetContents)
import System.Process
import System.Exit
-- import Katip
-- import Data.Vinyl (ElField(..))
-- import Control.Lens hiding (Identity)
-- import Control.Lens.TH
import Frames.TH
import Frames
-- import Frames.CSV
-- for Record
-- import Frames.Rec (Record(..))
-- import Frames.ColumnTypeable
import Data.List (intercalate)
-- for symbol
-- import GHC.Types
import qualified Control.Foldl as L
import Language.Haskell.TH
-- import Language.Haskell.TH.Syntax
-- import Lens.Micro
-- import Lens.Micro.Extras
import Control.Lens
-- import qualified Data.Vector as V
import Data.Word (Word16, Word32, Word64)

-- instance Parseable TsharkField where
--   representableAsType
-- parse :: MonadPlus m => Text -> m (Parsed a) 
    -- parse text = return $ Definitely



-- TODO we should create a RowGen

-- tableTypes is a Template Haskell function, which means that it is executed at compile time. It generates a data type for our CSV, so we have everything under control with our types.
-- tableTypes "Packet" "data/server_2_filtered.pcapng.csv"
-- type PcapFrame = Frame Packet


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


-- colDec prefix rowName colName colTypeGen = do
-- rowGenFromFields :: [TsharkFieldDesc] -> RowGen a
-- rowGenFromFields fields = RowGen
--       (map (T.unpack fullname) fields) -- column names
--       "" -- table prefix
--       "|" -- separator
--       "Packet" -- packet name (rowTypeName)
--       Proxy .       -- column universe
--       produceTokens -- line reader

--   (map (\(shortName, desc) -> declareColumn x) baseFields)
-- [Q Type]


-- on veut la generer
-- [[t|Ident Int|], [t|Happiness|]]
-- tableTypesExplicit' :: [Q Type] -> RowGen a -> FilePath -> DecsQ
-- tableTypesExplicit'
tableTypes "Packet" "data/test-simple.csv"

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

type PcapFrame = Frame Packet


data TsharkParams = TsharkParams {
      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      tsharkReadFilter :: Maybe String
    }

-- nub => remove duplicates
getTcpStreams :: PcapFrame -> [Int]
getTcpStreams ps =
    L.fold L.nub (view tcpStream <$> ps)


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
              "-r", show pcapFilename,
              "-E", "separator=" ++ show (csvDelimiter tsharkParams)
            ]
        -- if self.profile:
        --     cmd.extend(['-C', self.profile])
        args :: [String]
        args = (start ++ opts ++ readFilter ) ++ map T.unpack  fields

        opts :: [String]
        opts = foldr (\(opt, val) l -> l ++ ["-o", opt ++ ":" ++ val]) [] (tsharkOptions tsharkParams)

        readFilter :: [String]
        readFilter = case tsharkReadFilter tsharkParams of
            Just x ->["-2", "-R", x]
            Nothing -> []

        fields :: [T.Text]
        fields = ["-T", "fields"] ++ Prelude.foldr (\fname l -> l ++ ["-e", fname]) [] fieldNames

-- TODO pass a list of options too
-- TODO need to override 'WIRESHARK_CONFIG_DIR' = tempfile.gettempdir()
-- (MonadIO m, KatipContext m) =>
exportToCsv ::  TsharkParams ->
                FilePath  -- ^Path to the pcap
                -> FilePath -> Handle -- ^ temporary file
              -- ^See haskell:readCreateProcessWithExitCode
                -> IO (FilePath, ExitCode, String)
exportToCsv params pcapPath path fd = do
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
      fields :: [T.Text]
      fields = map (\(_, desc) -> fullname desc) baseFields

-- No instance for (Vector (VectorFor Word32) Word32

-- No instance for (Parseable Word32)
-- "data/server_2_filtered.pcapng.csv"
loadRows :: FilePath -> IO PcapFrame
loadRows _path = undefined
-- inCoreAoS (
    -- readTableExplicit path
    -- first arg is [Q Type]
    -- tableTypesExplicit'
  -- -- [[t|Ident Int|], [t|Happiness|]]
  -- [e| map (\x -> colType x) baseFields|]

  -- rowGen
    -- { rowTypeName = "Person"
    -- }
    -- path
    -- )

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

