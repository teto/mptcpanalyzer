module Mptcp.Reinjections
where


{-
    look at reinjections on the receiver side, see which one is first
    packets with reinjected_in_receiver are (at least they should) be the first DSN arrived.

    Returns:
        a new dataframe with an added column "redundant" and "time_delta"
-}
