module Net.Mptcp.Flags
where

data MptcpFlag = MptcpFlagFin | MptcpFlagSyn | MptcpFlagRst | MptcpFlagPsh
    | MptcpFlagAck | MptcpFlagUrg | MptcpFlagEcn | MptcpFlagCwr | MptcpFlagNonce
        deriving (Eq, Show, Bounded, Generic)

-- values are power of 2 of the flag
instance Enum MptcpFlag where
    toEnum 0 = MptcpFlagFin
    toEnum 1 = MptcpFlagSyn
    toEnum 2 = MptcpFlagRst
    toEnum 3 = MptcpFlagPsh
    toEnum 4 = MptcpFlagAck
    toEnum 5 = MptcpFlagUrg
    toEnum 6 = MptcpFlagEcn
    toEnum 7 = MptcpFlagCwr
    toEnum 8 = MptcpFlagNonce
    toEnum n = error $ "toEnum n: " ++ show n

    fromEnum MptcpFlagFin = 0
    fromEnum MptcpFlagSyn = 1
    fromEnum MptcpFlagRst = 2
    fromEnum MptcpFlagPsh = 3
    fromEnum MptcpFlagAck = 4
    fromEnum MptcpFlagUrg = 5
    fromEnum MptcpFlagEcn = 6
    fromEnum MptcpFlagCwr = 7
    fromEnum MptcpFlagNonce = 8
    -- fromEnum _ = error $ "fromEnum not implemented"

    enumFrom     x   = enumFromTo     x maxBound
    enumFromThen x y = enumFromThenTo x y bound
      where
        bound | fromEnum y >= fromEnum x = maxBound
              | otherwise                = minBound

