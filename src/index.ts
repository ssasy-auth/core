import { Wallet } from "./wallet";
import { KeyModule } from "./modules/key-mod";
import { CryptoModule } from "./modules/crypto-mod";

export default {
  /**
   * Abstracts the key management and cryptographic operations
   */
  Wallet,
  /**
   * Low-level key operations
   */
  KeyModule,
  /**
   * Low-level cryptographic operations
   * */
  CryptoModule
};