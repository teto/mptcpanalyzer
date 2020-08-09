module Connection
where

import Net.Tcp

type Score = Int

-- instance Eq TcpConnection where
--     -- (==) :: a -> a -> Bool infix 4
--     (==) con1 con2 = srcIp con1 == srcIp con2



compareConnections :: TcpConnection -> TcpConnection -> Score
compareConnections con1 con2 =
  case con1 == con2 of
      True -> 100
      False -> score'
  where
    score' :: Int
    score' = (0 +) . sum . map fromEnum $ [
          (if srcIp con1 == srcIp con2 then 10 else 0) :: Int,
          (if dstIp con1 == dstIp con2 then 10 else 0)
        ]

