module Text.Crypt

import public Data.DPair

%default total

--------------------------------------------------------------------------------
--          FFI Bindings
--------------------------------------------------------------------------------

%foreign "C:idris_gensalt,libcrypt-idris"
prim__gensalt : String -> Bits32 -> PrimIO String

%foreign "C:idris_crypt,libcrypt-idris"
prim__crypt : String -> String -> String

%foreign "C:idris_checksalt,libcrypt-idris"
prim__checksalt : String -> Int

%foreign "C:idris_checkphrase,libcrypt-idris"
prim__checkphrase : String -> Int

%foreign "C:idris_crypt_check,libcrypt-idris"
prim__cryptcheck : String -> String -> Int

--------------------------------------------------------------------------------
--          Types
--------------------------------------------------------------------------------

||| Quality of a salt/setting string to be used for hashing
||| a passphrase. This can also be the prefix of an already
||| encrypted string. `Legacy` means that the settings are
||| no longer considered to be strong enough and their usage
||| is discouraged.
public export
data SaltQuality = OK | Invalid | Legacy

public export
Eq SaltQuality where
  OK      == OK      = True
  Invalid == Invalid = True
  Legacy  == Legacy  = True
  _       == _       = False

export
Show SaltQuality where
  show OK      = "OK"
  show Invalid = "Invalid"
  show Legacy  = "Legacy"

public export
data CryptMethod =
    YesCrypt
  | GhostYesCrypt
  | SCrypt
  | BCrypt
  | SHA512Crypt
  | SHA256Crypt

public export
Eq CryptMethod where
  YesCrypt      == YesCrypt      = True
  GhostYesCrypt == GhostYesCrypt = True
  SCrypt        == SCrypt        = True
  BCrypt        == BCrypt        = True
  SHA512Crypt   == SHA512Crypt   = True
  SHA256Crypt   == SHA256Crypt   = True
  _             == _             = False

export
Show CryptMethod where
  show YesCrypt      = "YesCrypt"
  show GhostYesCrypt = "GhostYesCrypt"
  show SCrypt        = "SCrypt"
  show BCrypt        = "BCrypt"
  show SHA512Crypt   = "SHA512Crypt"
  show SHA256Crypt   = "SHA256Crypt"

export
cryptPrefix : CryptMethod -> String
cryptPrefix YesCrypt      = "$y$"
cryptPrefix GhostYesCrypt = "$gy$"
cryptPrefix SCrypt        = "$7$"
cryptPrefix BCrypt        = "$2b$"
cryptPrefix SHA512Crypt   = "$6$"
cryptPrefix SHA256Crypt   = "$5$"

||| Minimal computational cost to specify when using
||| the given hashing method. The `cost` parameter
||| in the `gensalt` method should be in the range
||| `[MinCost c, MaxCost c]`, where `c` is the hashing method
||| (`CryptMethod`) to be used.
public export
MinCost : CryptMethod -> Bits32
MinCost YesCrypt      = 1
MinCost GhostYesCrypt = 1
MinCost SCrypt        = 6
MinCost BCrypt        = 4
MinCost SHA512Crypt   = 1000
MinCost SHA256Crypt   = 1000

||| Maximal computational cost to specify when using
||| the given hashing method. The `cost` parameter
||| in the `gensalt` method should be in the range
||| `[MinCost c, MaxCost c]`, where `c` is the hashing method
||| (`CryptMethod`) to be used.
public export
MaxCost : CryptMethod -> Bits32
MaxCost YesCrypt      = 11
MaxCost GhostYesCrypt = 11
MaxCost SCrypt        = 11
MaxCost BCrypt        = 31
MaxCost SHA512Crypt   = 999999999
MaxCost SHA256Crypt   = 999999999

||| Proof that the given computational cost is a valid
||| value for the given hashing method
public export
0 InRange : CryptMethod -> (cost : Bits32) -> Type
InRange cm c = (MinCost cm <= c && c <= MaxCost cm) === True

||| Check if the given passphrase is of the correct size
||| to be used in the hashing functions. (Passphrases are limited
||| to a length of 512 bytes, including the terminal zero character)
export
checkphrase : (phrase : String) -> Bool
checkphrase phrase = prim__checkphrase phrase /= 0

||| A refined string which has been shown to be a valid
||| passphrase.
public export
0 Passphrase : Type
Passphrase = Subset String (\x => checkphrase x === True)

||| Checks a string to be a valid passphrase for hashing and
||| wraps it together with the resulting proof of validity.
export
refinePassphrase : String -> Maybe Passphrase
refinePassphrase str with (checkphrase str) proof eq
  _ | True  = Just (Element str eq)
  _ | False = Nothing

||| Validates the given string for having a correctly formatted
||| prefix consisting of the hashing method, computational cost,
||| and salt to use when encrypting a passphrase. Both, already
||| hashed passphrases and the string returned from `gensalt`
||| should have valid prefixes, and should therefore be usable
||| for hashing passphrases.
export
checksalt : (salt : String) -> SaltQuality
checksalt salt = case prim__checksalt salt of
  0 => OK
  2 => Legacy
  _ => Invalid

||| A refined string which has been shown to be a valid
||| salt.
public export
0 Salt : Type
Salt = Subset String (\x => checksalt x === OK)

||| Alias for `Salt`
public export
0 Hash : Type
Hash = Subset String (\x => checksalt x === OK)

||| Checks a string to be a valid salt for hashing and
||| wraps it together with the resulting proof of validity.
export
refineSalt : String -> Maybe Salt
refineSalt str with (checksalt str) proof eq
  _ | OK = Just (Element str eq)
  _ | _  = Nothing

||| Alias for `refineSalt`
export %inline
refineHash : String -> Maybe Hash
refineHash = refineSalt


--------------------------------------------------------------------------------
--          Functions
--------------------------------------------------------------------------------

||| Generate a random salt for usage as the `settings` argument
||| in the hashing functions.
|||
||| Implementation note: This fails on rare occasions for as of yet
||| unknown reasons. Rerunning seems to fix it, though.
export
gensalt :  (cm    : CryptMethod)
        -> (cost  : Bits32)
        -> (0 prf : InRange cm cost)
        => IO String
gensalt cm cost = fromPrim (go 100)
  where go : Nat -> PrimIO String
        go Z     w = prim__gensalt (cryptPrefix cm) cost w
        go (S n) w =
          let MkIORes str w2 := prim__gensalt (cryptPrefix cm) cost w
           in case checksalt str of
                Invalid => go n w2
                _       => MkIORes str w2

||| Hash the given passphrase with the given salt.
||| Usually, it is best to generate a new salt when hashing
||| a passphrase for the first time, so consider using
||| `crypt` instead.
export %inline
cryptWithSalt : Salt -> Passphrase -> String
cryptWithSalt (Element s _) (Element p _) = prim__crypt s p

||| Hash a passphrase with the given method and computational
||| cost. This will first generate a new random salt, therefore,
||| this runs in `IO`.
export
crypt :  (cm     : CryptMethod)
      -> (cost   : Bits32)
      -> (phrase : Passphrase)
      -> (0 p1   : InRange cm cost)
      => IO String
crypt cm cost (Element p _) = do
  salt <- gensalt cm cost
  pure $ prim__crypt salt p

||| Hash a passphrase with the given method and computational
||| cost. This returns `Nothing` if the passphrase is invalid
||| (i.e. longer than 512 bytes), or the hashing procedure itself
||| fails to generate a valid salt (which is a highly unlikely thing
||| to happen).
export
cryptMaybe :  (cm     : CryptMethod)
           -> (cost   : Bits32)
           -> (phrase : String)
           -> (0 p1   : InRange cm cost)
           => IO (Maybe Hash)
cryptMaybe cm cost phrase = do
  Just pp <- pure (refinePassphrase phrase) | Nothing => pure Nothing
  hash    <- crypt cm cost pp
  pure (refineHash hash)

||| Check a clear-text passphrase against a hashed passphrase.
||| If the hash is prefixed with a valid salt (as verified with
||| `checksalt hash`), the hashing method, computational cost, and
||| salt to be used will be extracted from the `hash`.
export %inline
cryptcheck : Hash -> String -> Bool
cryptcheck (Element h _) str =
  let Just (Element p _) := refinePassphrase str | Nothing => False
   in prim__cryptcheck h p == 0
