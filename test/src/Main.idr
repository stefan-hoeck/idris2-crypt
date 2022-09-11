module Main

import Data.Maybe
import Data.SOP
import Data.Vect
import Debug.Trace
import Hedgehog
import Text.Crypt
import System

--------------------------------------------------------------------------------
--          Generators
--------------------------------------------------------------------------------

record CryptSetting where
  constructor CS
  method : CryptMethod
  cost   : Bits32
  0 prf  : InRange method cost

Eq CryptSetting where
  CS m1 c1 _ == CS m2 c2 _ = m1 == m2 && c1 == c2

Show CryptSetting where
  showPrec p (CS m c _) = showCon p "CS" (showArg m ++ showArg c)

toSetting : CryptMethod -> Bits32 -> CryptSetting
toSetting cm c with (MinCost cm <= c && c <= MaxCost cm) proof eq
  _ | True  = CS cm c eq
  _ | False = CS YesCrypt 1 Refl

-- we can't check all possible settings as the computational
-- cost for some of the is far too high
setting : Gen CryptSetting
setting = choice
  [ toSetting YesCrypt      <$> bits32 (linear 1 7)
--  , toSetting GhostYesCrypt <$> bits32 (linear 1 7)
--  , toSetting SCrypt        <$> bits32 (linear 6 8)
--  , toSetting BCrypt        <$> bits32 (linear 4 11)
--  , toSetting SHA512Crypt   <$> bits32 (linear 1000 10000)
  ]

passphrase : Passphrase -> Gen Passphrase
passphrase p = 
  fromMaybe p . refinePassphrase <$> string (linear 1 50) printableAscii

--------------------------------------------------------------------------------
--          Properties
--------------------------------------------------------------------------------

unsafeSalt : CryptSetting -> String
unsafeSalt (CS m c _) = unsafePerformIO (gensalt m c)

roundtrip : Passphrase -> Property
roundtrip p = property $ do
  [cs, pw]  <- forAll $ np [setting, passphrase p]
  salts     <- pure (unsafeSalt cs)
  Just salt <- pure (refineSalt salts)
    | Nothing => failWith Nothing "failed to generate salt"

  hashs     <- pure (cryptWithSalt salt pw)
  footnote "Hash: \{hashs}"
  Just hash <- pure (refineHash hashs)
    | Nothing => failWith Nothing "failed to hash \{fst pw}."
  cryptcheck hash pw === True


main : IO ()
main = do
  Just pw <- pure (refinePassphrase "top secret")
    | Nothing => die "Failed to refine passphrase"
  test . pure $ MkGroup "Crypt" [("prop_roundtrip", roundtrip pw)]
