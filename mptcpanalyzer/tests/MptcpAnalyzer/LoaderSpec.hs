module MptcpAnalyzer.LoaderSpec (
spec
) where
-- import           Test.Tasty
-- import           Test.Tasty.HUnit
import Data.Maybe (fromJust)
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import MptcpAnalyzer.ArtificialFields
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



-- TODO test (nombre de paquets par exemple ?)
-- buildAFrameFromStreamIdTcp
spec :: Spec
spec = describe "Checking pcap loader" $ do
  it "test" $
    pendingWith "test"
