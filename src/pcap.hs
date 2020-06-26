module Loader
where


-- TODO DateField / List
-- use higher kinded fields ?
data Field t = Field {
        fullname :: String
        -- , type: Any  -- 
        -- |How to reference it in plot
        , label :: Maybe String
        -- |Wether to take into account this field when creating a hash of a packet
        , hash :: Bool
        -- , converter :: a
        -- converter: Optional[Callable]
    } deriving (Read, Generic)

data TsharkParams = TsharkParams {

      tsharkBinary :: String,
      tsharkOptions :: [(String, String)],
      csvDelimiter :: Char,
      readFilter :: Maybe String
    }

-- |Generate the tshark command to export a pcap into a csv
-- 
generateCsvCommand :: [String] -- |Fields to exports e.g., "mptcp.stream"
          -> FilePath    -- | path towards the pcap file
          -> TsharkOptions
generateCsvCommand fieldNames pcapFilename tsharkParams =
    start ++ opts ++ readFilter ++ fields
    where
    -- for some reasons, -Y does not work so I use -2 -R instead
    -- quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
    -- single-quotes, n no quotes (the default).
    -- the -2 is important, else some mptcp parameters are not exported
        cmd = [
              tsharkBinary tsharkParams,
              "-r", inputFilename,
              "-E", "separator=" ++ (csvDelimiter tsharkParams)
            ]
        -- if self.profile:
        --     cmd.extend(['-C', self.profile])

        opts = map (\opt val -> ["-o", opt ++ ":" ++ val]  ) tsharkOptions

        readFilter = case readFilter tsharkParams of 
            Just x ->["-2", "-R", x]
            Nothing -> []

        fields = ["-T", "fields"] ++ map (\f -> ["-e", f]) fieldNames

-- derive from Order ?
-- define as a set ?
tsharkOptions :: [(String, String)]
tsharkOptions = [
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
      .tsharkBinary = "tshark",
      tsharkOptions = ,
      csvDelimiter = "|",
      readFilter = Nothing

}


baseFields :: [TsharkField]
baseFields = [
    Field "frame.number" "packetid" 'UInt64' False False,
    Field "frame.interface_name" "interface" 'category' False False,
    Field "_ws.col.ipsrc"  "ipsrc" str False False,
    Field "_ws.col.ipdst" "ipdst" str False False,
    Field "ip.src_host" "ipsrc_host" str False False,
    Field "ip.dst_host" "ipdst_host" str False False,
    Field "tcp.stream" "tcpstream" 'UInt64' False False,
    Field "tcp.srcport" "sport" 'UInt16' False False,
    Field "tcp.dstport" "dport" 'UInt16' False False,

        self._tshark_fields.setdefault("reltime", FieldDate("frame.time_relative",
            str, "Relative time", False, None))
        self._tshark_fields.setdefault("abstime", FieldDate("frame.time_epoch", str,
            "seconds+Nanoseconds time since epoch", False, None))
    ]

mptcpFields :: [TsharkField]
mptcpFields = [
]
    

        # np.float64
        # self.add_field("frame.time_epoch", "abstime", None,
        #     "seconds+Nanoseconds time since epoch", False, None)
        # TODO use 'category'
        # rawvalue is tcp.window_size_value
        # tcp.window_size takes into account scaling factor !
        self.add_field("tcp.window_size", "rwnd", 'Int64', True, True)
        self.add_field("tcp.flags", "tcpflags", 'UInt8', False, True, _convert_flags)
        # TODO set hash to true, isn't needed after tcpflags ?
        self.add_field("tcp.option_kind", "tcpoptions", None, False, False,
            functools.partial(_load_list, field="option_kind"), )
        self.add_field("tcp.seq", "tcpseq", 'UInt32', "TCP sequence number", True)
        self.add_field("tcp.len", "tcplen", 'UInt16', "TCP segment length", True)
        self.add_field("tcp.ack", "tcpack", 'UInt32', "TCP segment acknowledgment", True)
        self.add_field("tcp.options.timestamp.tsval", "tcptsval", 'Int64',
            "TCP timestamp tsval", True)
        self.add_field("tcp.options.timestamp.tsecr", "tcptsecr", 'Int64',
            "TCP timestamp tsecr", True)


-- tsharkPrefsToString :: TsharkPrefs -> String
-- tsharkPrefsToString = 

