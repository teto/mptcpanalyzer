module MptcpAnalyzer.LoaderSpec (
spec
) where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import Net.IP
import Net.IPv4 (localhost)
import Net.Tcp.Connection
import System.Exit (ExitCode(ExitSuccess))
import System.IO
import Test.Hspec
import Test.QuickCheck hiding (Success)
import Tshark.Main
import MptcpAnalyzer.ArtificialFields
import Data.Maybe (fromJust)



-- TODO test (nombre de paquets par exemple ?)
-- buildAFrameFromStreamIdTcp
spec :: Spec
spec = describe "Checking pcap loader" $ do
  it "test" $
    pendingWith "test"
