module PcapSpec where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import           Test.Hspec
import           Test.QuickCheck                    hiding (Success)
import           MptcpAnalyzer.Pcap



main :: IO ()
main = hspec $ do
  describe "absolute" $ do
    it "returns the original number when given a positive input" $
      numberToTcpFlags 2 `shouldBe` [TcpFlagSyn]
      -- numberToTcpFlags 8 `shouldBe` [TcpFlagAck]
      -- numberToTcpFlags 10 `shouldBe` [TcpFlagAck, TcpFlagSyn]

-- spec :: Spec
-- spec = do
--   describe "JSON bi-directional conversion" $ do
--     it "ResType"      . property $ (propJSON :: ResType -> Property)
--     it "ExtraInfo"    . property $ (propJSON :: ExtraInfo -> Property)
--     it "ResVals"      . property $ (propJSON :: ResVals -> Property)
--     it "OneRes"       . property $ (propJSON :: OneResIDU -> Property)
--     it "SolverResult" . property $ (propJSON :: SolverResult -> Property)
--     it "ModelResult"  . property $ (propJSON :: ModelResult -> Property)
