{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
-- https://hspec.github.io/hspec-discover.html
import qualified Spec
import Test.Hspec.Formatters
import Test.Hspec.Runner

main :: IO ()
main = hspecWith defaultConfig {configFormatter = Just progress} Spec.spec
