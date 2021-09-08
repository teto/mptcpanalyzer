-- TODO make as plugin
module MptcpAnalyzer.Plots.Stream
where




-- import Diagrams.Backend.Rasterific
-- import Diagrams (dims2D, width, height)
-- import Frames
-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

-- import Katip

-- where expect a parser
-- class Plot
--
-- mkPlot :: IO ()
-- mkPlot = do env <- defaultEnv bitmapAlignmentFns 640 480
--     let chart2diagram = fst . runBackendR env . toRenderable . execEC
--     xs <- runSafeT $ P.toListM fisherIncomeData
--     let d = chart2diagram $ do
--               layout_title .= "Farmer/fisher Income vs Age"
--               layout_x_axis . laxis_title .= "Age (Years)"
--               layout_y_axis . laxis_title .= "Capital Gain ($)"
--               plot (points "" (map (view age &&& view capitalGain) xs))
--         sz = dims2D (width d) (height d)
--     renderRasterific "plot2.png" sz d

-- Manually fused folds
-- main :: IO ()
-- main = do ((age_,inc,n), _) <- runSafeT $
--                                P.fold' aux (0,0,0::Double) id fisherIncomeData
--           putStrLn $ "The average farmer/fisher is "++
--                      show (fromIntegral age_ / n) ++
--                      " and made " ++ show (fromIntegral inc / n)
--   where aux !(!sumAge, !sumIncome, n) f = (sumAge + f^.age, sumIncome + f^.capitalGain, n+1)

