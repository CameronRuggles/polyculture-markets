//! Direct Payments v1 integration tests against a real PostgreSQL.
//! Requires DATABASE_URL; skipped silently when unset (same pattern as
//! stage1_db.rs). Covers the coordinator's required cases: batch
//! validation rejections, canonical rebuild mismatch, allocation
//! concurrency, cancel-retires-entry, pool-empty refusal, mark-paid
//! authorization, and byte-exact round-trip from upload to assignment
//! (the data the payment page renders).

use app::orders::{apply_action, create_order_with_config, OrderError};
use app::payments::{
    assignment_for_order, canonical_message, expire_unpaid_orders, mark_paid, payment_seller_id,
    set_primary_address, unused_count, upload_batch, PaymentConfig, PaymentError,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

// Real stagenet fixtures (Stage 6 fixture wallet, wallet RPC verified).
const PRIMARY_A: &str = "55b6gZhKJ2b6EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7H9AdnFB";
const PRIMARY_B: &str = "57AaCDLE3GeBsgrK513QiUFePcBbSp5QYhn2Q2S1P9DsceUmeVkvBMJBQDFTfS9f21LfhXJSWNGN16mvXQmffGsA7KCVBxh";
// Disjoint slices per test (SUBS[0..3] for the batch-validation test,
// 10s for limits, 20s concurrency, 30s cancel, 40 pool-empty, 50s
// mark-paid, 60 byte-exact, 70s primary-change, 80s expiry, 90s drain):
// the global destinations uniqueness makes shared fixture addresses
// collide across parallel tests, exactly as designed.
const SUBS: &[&str] = &[
    "7B2BSyZukau1TerLFtd6UtDvgz7YZVKGmV9xNowvh74biBFvjXTcWAu8EMJ1ot7sCHHCXrg6QRTHgNfoGsQRRj3xRqNnPFd", // 0
    "77cfgTU2rrsVSKhJzJohXzJBkx4cnJTPHDWK6sRxNT9U2cksSvg5mnTMV78PbMuA1mhvm5RaFgUV7DFc4ze9yq5jTwTPPpc", // 1
    "7BMUYtFiouid14Qret4pFbe26a5pUri7mifsd3hAW8CX5mV3N42AcsyAE5csiFgdFe6xZyet1PgVQ7g864RLMXdZ5raBeQ4", // 2
    "79P6EcofPJEKRX3ErDWChmeGc6adA7kwPGxMvyJaVvBm9nHWpQK1RzWSw1Du5ur5E339Ai93awP9u6kxazUZxGmYQsUvZpz", // 3
    "72zUPzmAyxP9LCJo6Kdg9wGsM4e3H3mKXSr2mYuTAz9rcDcFNseejEENQu75wgzEtD7HgUWL2GWXe5sdWH2hGsEXHvR8thM", // 4
    "77igFNto2xnREKwpur11dBUUcCshQVjNZH31BNbZNbJccE3S39RfqHVTA4eNc832v66bCSfvMcwX5fyT1oMYZ2WXFtCcJNh", // 5
    "72bvDCpnxUCaxeEhGX7CLQZvriyks7nAE71Fr8H5m4dSLCtTx1k2zbkNratUJfvnR6RqiThBoc6KqPt96b3VznVaLKLbrkK", // 6
    "755behWV1epaqDGdUYqGkqa5yEc2KceXLJ2VZBqKhJAXM4n6CMFCdbQMVVCF6bSCQxHtC3Jj6XRXHHaAD2n9rPYSN2vXhpC", // 7
    "75iLCeUEX4m8Pn7fSRv9vYEr7iFLbGQngaxA5yn8d9Q3GgU1juihAVW9U4ErsvvyeD3o7np233yxoMmegtZyZuWdBQbMnbs", // 8
    "7AcYxXXxeNU9xrfjKdKCFPGPv5S8CgkXD1bcrL7bPdHiLzemA8tfUYs4JpcTUvRvyyHq5zfkM9YBK99F3F27oNKiG1vUAsE", // 9
    "72GeiPtUwSSSsbBtk7SgYGebrQYiDZZYvGa7Y5Z5AAi2M5Cpp38sCU8DjQtcCVJPTxUjua8ekmSuRhzNSz6gFcfFErM7Jqm", // 10
    "7BszKBeTw4S4kgFQBXCvDhjHGmaKJN5o6NXzYfgqHDCHevkKpimu65oSV1amFYmDRJgjrP2PUEW6D9r65j1aChu4KVDpFYN", // 11
    "7834gBEu9ZvVws43iY7A7pVPseMrX2En1Ugugek2nKZBEwpkRhTHREP3xt8zgHH4sudXGhKb3YUVfW7Pim3Q4kok7ooS8di", // 12
    "75yiSJ4bwkrhNhrXHCMSuA39RG3VFdZuLGwyp9B5FcBFc9BMr5T6iKc1qzV9WqmeukGVTWNS5aCAJ7d1XwEaGHa92gB4NjH", // 13
    "72vJvHyqyzAUr6SZcKRL6K2DRMAWnpo6YRhaRRt5dcK3JUKXWo1cF2UELEghFMC1HTDNyABR4RQX42gjsxW7vgX3Bw1ckrk", // 14
    "785xfNLPLRxTgA3gPzrFPsMKgdH36zVz91F2GMuBtFfXVMnHV2SLcKUM1QHFw1YDGFJsj79EKCvPei7qhQM9YPySS4nToXA", // 15
    "73iL5FxK8Jd2Ar6tMTqfoQNBnoSAneajXbimY58QpEPVBLLXJ4h1xBAR2o8i9FzcNQKnUHkTcMhxdLmMvi6Rxag37CAva8Z", // 16
    "785RveUUgtERFR3SZTcjc2XgSoFa6U1447goAeWr4kEaWtkLpfadrwZFajjkRFiQEeUUsJgqmB3rHFXk3ZPwk2hu64r6buD", // 17
    "74CpuTiAE6dHyesS1TCwZhWzaXThYA5NKHjQyvfpkcFAXSi7nH2DHWsLV6WQ8kNgdYXBMZYtyZZ1ma55EFpZtqFdMYaycHo", // 18
    "7BkAtf3c9ALTVMWqJE6QB6gZnDootgMe31iYxFNCVerM65XJaRtkMhifQAHss4bz4P3D6eywa9FGY93ihkmtcaMgPxL7WPm", // 19
    "732icYh9vuLWLNp163DJo7WX919X9T9HMau2ShdmV8FyGjC54fRFMcaiYgtRPxHPhFbThLMScPnemRmNjtMbtQZjM7631fU", // 20
    "74VrmqfKP3ZdQudxpvYdXagEaVMe38FU6B7vpLsZpt6AESb6bwGKGMkjK4m5zB2HGWU1AACxBoCukYXzAmi15F49U6mwVFF", // 21
    "74fRyWX4hrfgELFmkbCin8G1Z3HEFNPcDFSpPqs7AFzuU9juWRSVSEfTodHzYicVGpWBC6ykTcmXk6CyqT5Vypr7K2Qj4GD", // 22
    "72ckK45jjG4BUx8EbtjYpUV3Sdd3vUcVvXDjyuhWJZDec1LFt9ptF8pUm8e4anULYBPxtTzDBAdGJM8rJRkFsgrHC9H9r5o", // 23
    "771spwVKVSnGPhi9mv7tvdW3QExdLY1riSz47aJJrbaHZSfSEna4WKh7oJANbPUeeeJ2V8QnPSvtr9v43V53v3cD5DRruiK", // 24
    "75q6mnAVn67Z76P8naAX6xZwtz5XU6gxC4cV186WgfzzXaTZHbUkGjyPLZJMFiNS8T2aLupbBJbu9aPmSa1Wr4Mr6ar7HBq", // 25
    "7438fLZpM191GVnBSGLXGhZKRGYekjnCTFQYuYwDLWeCbD3CdEq4wVSRtoLNRuunii3p6s64w5dZ7XjXgYTcMBhYNSvhgaD", // 26
    "73z4w2u1Kp36Je3yMan8c31WtX4FVyGcA9QdUFJt83ojGHUNwRuTfArSPquaxWRgNJL8qQWga1bFY4b3y8Vk4o9m8Ss99ug", // 27
    "78wVpM1gYWjWtoDn4njevygX5csuV47cg2hwDAiG1KFs1o2AvPT9wpMJK7LTjFFiQX2CtBnhaXA2bik9QYyaNfzU6jyvHkX", // 28
    "731qVfEwDYQSeMwkdNM5rLJoXeU7BePitgaX4pzp9RY9TCR6bDkQdB2QTX7t23Xscn3hTVH797Kc8PoXYPFN2h7rVhK5UJC", // 29
    "783r3SJfEeq2TLJSTSXjm1Z8JoV63LTH3ECPGSpfCkXLBtiMAUGCPcxCZZAkhqgA8niy4W1vTN8GijCjKebhWR4fULMWMM6", // 30
    "773hwRJWn1ijHNRL534psKL2PyQGvdVoEbALUcsedCeXe9g45Sa8vgnAESSAwcJrXgGVP5DmvJkYwFXo3EMLpeoMPqUhryP", // 31
    "75nicyHTYvqfvEHNoiHPhjaoVbYDCeSNZUHCgL42a6zM2AebWzCWPht9KC3CA3Z81jjYrhkPT4n1G8S6NiAgJLwASQiMaga", // 32
    "79CtXK81pTH1Q86s8bZzT13tFCJFEYZwbS95TCTNuHjZ1pjRsLnGsVcAnMSPBTZE7RGYm5e6CRfkxY2z3XfVPwN2LomPFUX", // 33
    "79sovKTuhwwLyGYrJQpzdmVGXpTwhtqhy3dcYutQP5B7PJvk4s8xDqf6GEpfHHk5LXdHMBNCL2BJ7BXcMfUns76TF5oTTiB", // 34
    "738oaz4yzQnEF8SQyt7fdP5DvnWFQZhFh5TQT9FzdDu4SUQKLjjZjvwETNCZz2KpD567hgBcPRc2gJ14q5SJa2Yg4cm3hyE", // 35
    "77utxahrTD6hCAwxYBdTDwYNvZFu6rYiwcC7CR8cZqJfhNZsbPmdvzyCZtoZbffvn4DA8DXsUthZSh9Ju77STt5Z26KQ7Ap", // 36
    "77GiJb9VSrAE96g76t8PpP7cvRU5NjUHKaP2FMNmgGziJWd3wqGwBvQ5cErpNpaJL4RtWgQJNqNfmTVfL14J2zFYSGGW7ED", // 37
    "78KGzuvtboCaSjFJy6HFXFCRJRmFXUGuW62gpyNkEafgJvq7VtUuhKPXBpe7rHoNnQg5CWi3sqJh9YpfubwFTxZeQV6YsWf", // 38
    "77XBi4jtYBtaKBYnwCHMjzX1Wty6xkXwxbyeQKqTGkTa5RwVjYAk3skaEKRP4TUshm1U3VWaNKvaXb366LriBZc44zXq1hQ", // 39
    "7B1reoh1NomHeGvdv5uUy64U823ePrHDqcZ79L4FX1zG7qdL7gbziVzFosNu5ak3U8fYPi2mU9fwQ1ksZvZL4GDd3W2p7kE", // 40
    "75LZHcFNkC5QUwe962KvSF5jmo4An86ccQpGEV19zmpAWia6GpzV9ex6ArFDWHAN4P5xqg81X14LE1JFutdmSwUn8FHFser", // 41
    "78EBJBEnEQ7ebYw3XGSLS5Pxa6fXmkH2k1fWMzR1RGGAefdE8STrfVVMZX1fUJ4QYfg8jjVwUgVfUN3QmkCePAZ6N7emUNe", // 42
    "7ARQFxNVdLqPV71RW17w911K1tbAaupMuBfyRbZt5CioM9y8zNveUrPciAujmRrSJm6yjW5MYqc73V6k3KVNQjLQKrePYeR", // 43
    "7BJGbeT1GdKQXNJpSbPkcXbbDrrTscFGfKBFvcN6Wg5pbaiZcYXYjxhan1xBwqDo8SQ91dYDT4KVYMLv51mfcYTC5HQhK6N", // 44
    "75QHV4oP5QxcZPHnnDLjCVKdQLZvwrvAd4wg9jxjvU5LUG4AWnKWCHjfvukS6fGPEKdM6h9eGdPm8fxw673sudgKKnJkzbN", // 45
    "76NYn3AwAaxCTKXetQ196RU3UnHKqnWvTKnQBRPLL36K1BCfjtUCcsCY31oaoYPgHdg7JiyBUkNRCWbkBcicB652DgSjwQQ", // 46
    "72tG7uwvC622NQygsmcqZkaNLyXBMHyLAKHV4CNoYjdMA3vsea9JCJieZbzewuC6znLHHskYwKDzd1HK1RHciPGANJS2sg7", // 47
    "77pNthbFHwGGS7TW67eM4ZddTLANb1KMLaxSb2E5pHuofdCbBZQnAa6a13nRMzEN51iiW2EuaAJpHE4Kh8YGzZJR9U4MRT8", // 48
    "76V1MdgGEVaBTyenWShNs8BZrD5GLQUWscLgM8UFcZqUiganUJ6kakibbWgVboakvUF6UDVKKj1jxWeufDnvJEp1TzHViY4", // 49
    "75u5qH6EFpuL3vBtc2mpo9DNXKSJpY7C6Xfv4kRuZtKgSumgCnwKqY97BJbHx8s4yo4nfZMo7HJ88Uoojzr8Z4m1ArzbRSS", // 50
    "74w4NzDUTDZhcaKVhA73SNJ33erD54JRQ3e7hWJC3xXj8w9YNAJKpdM1BJKEzbxqvwCGeZwagEHXrgSC9w1UkC8Z44KcECJ", // 51
    "7BSCWfzSckBVfXZy1xFZyJEVN3t14DuUNHptHYiHL1q9GkPR58WqWpiVBrz6XfZgtx8Jgq7545WTZUrqpwkXx2rG82Zfd4b", // 52
    "75Ed1WsRWq234QEr1JkB4gXnwpaLnVa4QG4JLa15LVTfN4tT6tUQkH57RzCb8BMvQJMPHPdiWe4WMetyqmwnjf4m2Nta4St", // 53
    "77Nw56WdUR9UKQKo9UrqEbVdteCymaCauZczVjRb3Pii2RcJJekkKD21aJPJoa5XxsDoaJQiDAKsJKm2FgxszWGgEpZ6EKB", // 54
    "73tbUBxqsqrcrGiAEPZv5FLzwbsjtTwYiRwpx2oB8rvgbhNjoHhASUVYb7QocmgPNB3vUY3d4FS7v9WabtmFVCVUKukuG62", // 55
    "73dcZyPQHBLXWzrXH3uDUscHLV9TwMjqE3T39PdjeB8zZWeL78mKXmsf5PABQZD1UDfMEc9uEKFyNGegd18c9GxuCzgg9ih", // 56
    "7BANxmhHCTDW9aKjQRxG2CSLjwQyj2uFHj6dJmPgamFH8D8pmDarRQ1BuWXy7YJ8vVBs3LYUrPmzEVQHQe9o6H2v3owGPyN", // 57
    "7BY8nxzQDk3NY93ZHVbzNyMUCiVcx7qUS1rqN1miXtL1akY2otx9yfaUdTQQZUFmp6aCZp2SH2Z9xBVM3jL7bVQrCeWcdvA", // 58
    "74fFZEur61X928Yr1K1EQRU64XKnyNkm4BUMBCscdipv7XGDjDvdxLNWuXrfJq3Vby8VZsxSprRQMb3evQqM6ogt2HcrSoC", // 59
    "7BoD9Xp7TQVWTbybLG1ioy9iXNqAZMUapToRxMT1p627EvPAS86ifaF4dxA4eJN8pGMy21kZ1xCJxZxSakVdHmwRUxNNSgw", // 60
    "79RH7gLaZb3VxoxUCGGdCL4fYGwX8US4EGd7tfTQMFVcWhdrCXDkeXZ4PwzQy4XCbERAtH7kzfrHQFadKCfiGidvDfnTcgN", // 61
    "77UPvzfyE8W7ievY2pjjr64iWDpLzCt1NT5JurZ6pLx7LsxhBbpxxsJZXqAC7mhxFMgn4byjWwbEb3CVYnEYk39F8aBnYtZ", // 62
    "7AdKTmwRmSF5LDRE3rPUx7JeMYCXYfLzoQ3uDC6s69uWJtCeKeVBdyrjMspiHqgY4qcAViTS3XVJgNHMrJfrJeduFmGwQ4J", // 63
    "769SUfbmJGvZ5g4SehQh6nFqCMYqgBC6NVx33PcCYpsiTMqszqtXydoLawK2xKoyvCh6zgGKjuYEk6bzvVC6moSxFPobVQ4", // 64
    "72XvUHsvHsNLmzvND4SWHQbMfKUdoS4YEUnn5fR4vKp8T9fvCwqN75L6dpcSV8naFKNYt5cxAecxH9quKSURU6G7UzumEGX", // 65
    "737y5FcWvQ6Fk72NTiMkf1WFbB5v11srV49VUWXZXceTYrEAXM9fuLVHKnUufzfkjaRbjCwY3ujUFHYmNo24hgRfA9M1sYW", // 66
    "78nbNELiLMfQAsB5jP2FME3ibuVgZjh2keU3NcR7bH167xWKupXmRyB7TaweQcq1L5MspyHSGSB4D85MzRvwjET5TcPKcpF", // 67
    "79yVaPoy8wA1XUYb9go8FmN4McNUUr4ULRz5rvT6fYmq8q134j1M2DKekrZhKYder5jHdrvSvKri4Y6bjD4MYETXNNrFAZ6", // 68
    "77XAZ6NimmScag5vvP7CVc3CjRiECeZqJgjnUSJeE47W3z9cb59rwcQMgkXrCUMWHkJuqk1oe8Tz3RPQiAuzAtUgB571feM", // 69
    "791NcRXfjasCQRZWJk9Uu5fLorrrcg5VbWqFNmALG868JQXiZWUwvof36NAaYsdnsdeZcahwyduiMjRsaQotMn51KfymrSA", // 70
    "76KEA1SzAFU3N1eqY29Yg6HiUBLikPiZWWWsosQe2LD29kzSMgKQddD7u5cmgAkBwF2TtmFJ7K6aHfzmRQNxRfLKMk549uA", // 71
    "79VoDXGyDepb29rMG7cWLwTjrwqEMJkxkDzn6d1qF2A2Ds71Eog4cSBjRPjPRpVbdG5ew5e3cUQ6vP8qUyH7ZCvCMMgVXaQ", // 72
    "76CH7XrYvXG32QfrAW9VmN4aLWtXXVjp3FzDvUxeoxcrgsQ7jBHkDWDXTKrkXgmCML48XiPGQSgqFKP2sjkxwf9K5zaNLQP", // 73
    "7A5B88NpDy9ewCaDWEbotwj1JkT4CiisjTxSEMDEGRn1YnseABn3eYB4k72Qyr2gssBckvHkCXf1ZKJqVkvYeDvR9y6HicR", // 74
    "7AdeFu6rTSMc57cvRaaCAd3L5Go8MUXjnGUxNTgcDdwuaVUfpsdj7AZKPoj4hNeUGEjULW6CB9dFHCc3AN5gCy4YTgFgrTV", // 75
    "773ZEtoAmhRWuWrfWZUWfS69skWw9BLKY227U2NRS8eBHRvXMEjUaU1QXqMbCLCZJg7uu8X5mVRz8X2nnJC2LcyAEtzJ9dW", // 76
    "782eHBnHX7eCnmhAJ84uZaN5sDx1RiMCg6j8FPNewFVR3GFhQp7yncH4da37mkJ3gfHy32QbnFopYTDnBhdgeuUT4Khxpom", // 77
    "768GSTKLsGTK6nRWifGaKK2pZwdsxv12dcsV8HKcFeMjPLp6krfBp878ZiL4nrpFHE3oLwNYAUZDYZUnP8Sy5FHP6uAbS7W", // 78
    "78vH8urE6wHKUPDcgxBKpiMZVXw3TVYmgQk9zdiTLq3jWCWVL31MzfFUxqWs4JMB1aDV8TsCicPkz4omLf4V2di5GgcgWa2", // 79
    "76qazg4S62j1248T6JcYmM8hLBTuotz2j2Y8encnQYHNWRTB3QHd6ffDKKwC3R95TRSu82ivvwnGmLezF2zB1p7YHnCKxg8", // 80
    "784P8zdaYg8afr5LgQbWBj2HAyZ168oqwYVg4Y9bKtgWeRLhghhiANLZaEHsaTixqzNb6NrR7KN2mhGYZU6Vj2DoDnskiLG", // 81
    "7BfGv9RRDeZLhsUYY9yqkX3KK6fuwpTo5UBeCzerjTbFgQ3XZRa8o352BKhVoszTvwNE2zFH1wPHW1wphz5HZDLCJSsQMnU", // 82
    "73F5WCBPD2cBWKsND42RR7RAa4u4rqsWBcwveGjvhEARfqXViPwbACjer52zCQF6dF7AURq2665YAXzTxjNs7Dv6GxAX7ur", // 83
    "75mJkeRyoJq3MiDShxzpep159Ap72KXGVcT3fpaByRg39ge9JUabLmuFfBUt5vWyAkDX4NAtWraHXErufajAYqXeJWSRYVV", // 84
    "78wWu5D7GYq1ih8HJReYxqZxxmSMRc8B28gc6F33ktnfAXgVs48rVPMQdSHjUALEQs8TALtYcqs5M2ZBHJRjDZrs5bAUhUd", // 85
    "78C9eLrXAK67jf6KTNQvPoW1YbbnTQP7RQUYmSYFsgtsPseB5LkAx41ho5yYVRNzqn4hJg1c88vNq1QMnY2AudGJ7DVkZqt", // 86
    "776qUdZ7ffkRT5bHyc826pXcY9ESEoCBYTrn2jPrf6qD55EHkgRGiQYhTfcQ5nGeNranpamVCckJLPE4LnDUeKTBAra4a1B", // 87
    "77DWAZKfhNqarxMPMigZgy8zqdL67gdES42uiUjufXRJXTNstc9raTGXk6y9JhXXbVJcn4ZsC6NvejMdgs8HvQDhCMrgL6M", // 88
    "77kfvXxjnYie2bkK4K8eRC6s1P6QnF6QMaouacFwKQYfgfSca4ZZyLiUkDt4QfmzE4dRwm58cyATcS14CHsCuwLQKjDvRHB", // 89
    "78By68caRTTSUUqgSx5RZaVrZqRun2ymYKB25HF1DZgUgQTiZSbZ364hfK5AU26ft16MGFqKitoe22uyKdxPoubvMApyiVP", // 90
    "78U5MYvh21Tgiruu5BwsnyHvS2E7YWWDpXpUQ7um5zJd84W7EDGAQuzWCPTCDXBomCBs9mLAYUyMiPYZPeNW3TV2C3ZC39k", // 91
    "75KGWnMttoBjMkVAi2qiP4M4XsQbt9owZ6jD6wvwWAjiYZ3n4ZNBSwmFV5yNRCeWs9F7Xrz4jpNhA7Lg6crgJSuUUiwDEKK", // 92
    "72JeEmtD6mbMYhwepEDn99BLbdUcyuYKNBfdJk3ukNgo3KzhVc2dsc9djCp8Ghoymf85k3CyhS9mUTVfUfZD6ESuMywEEfj", // 93
    "73Wy1Zo5yGP4fU2ZFSd5YSBStiSUeUkuhVUxSLNZmzYSVitiCUVkRJH92gH4kfjVLwJyFaJeYgErq2bTPVfAvV6N865QPob", // 94
    "72KafY6oVGchVsWCxcD1MiCgjrTEsrqyfMEV9reafU49MMo1uSVe46gLTj1tDNEzUGKufA7RUESkgC1uva81wXqZ9N9dHQ3", // 95
    "73DKz4Uj112jTmquPQgBbYFKKNS5sKwrvKGMqS69vXumbAjWQ8dMtqLGJFXuRVJVLz3FBAouvHMBoWjxx6wa8VWSAGD5vCN", // 96
    "72pdkzyKL76MfpTXGiPPEyC18xguoFZNCdnPhNKFUidD5z3pLFua9mXYbJ85R96CQ54cSsjYhW49u4oD3m6juBykCsQjzV4", // 97
    "79E3Ewh1QsT4yfbKUMdDawH6TjgkASPMcNAEpcZjvqBS871ijHPGtWBf6DoPFXD4uAdtxeKPmnJFCXi32eJx65F2QZkqGuB", // 98
    "79MuEnZpEy1KBULL1aFaUuai8AT5pbRWpBGzhyNUMqp28q2XWXvAqVvLSJM69ZztGHTYiTgsaVpmFT5P9YpVNTqiRm5HZ4D", // 99
    "73L63m3TZ1kfQ52EGnv1TULs6n5iGpYy3UE2Vw237Ga5HbeByDAvnh157E8vgr34fzg6yw4DkXmje1mP99F4aStDUQvi7SS", // 100
    "74jUWbb6EU2D5JCXuvJSA9bEmhsZVHuxH7stuHtHqVx8CmFi35PNxpKWHQNrL34Mhb1mHUC6GvRvneQcTjUyXvWcV4eXRBN", // 101
    "73vjtBVdZc5FsDdp9HeiAt3MKPpWdMin2Kh3u1MHZ4gTC7iWYEqZPNTbCrpKMCtV1L6Wi6fMgMpidgf8ARUan6WGSqbz3wK", // 102
    "7BWMFSzzhFiPVqVVDenLN2P9HozaSx8D22ECNUr8Bnmjd7khwxtANSdYVkz37dHYrthvxedCGkYcpV6ZNNFPexmA2py3HzN", // 103
    "739gHEkXbvd9T8nT84AAoa1zPKe9DbghriWZg82sHMUCFhSneCqaQhvLpJBSpzDbbe2XcfZDiNPHTBfzbjpmRRawFFvjuqm", // 104
    "78b8yieEqt47rZ9H3oCzGGdBxnDwRPwcFT5XsbyfPrCu8JBCpLhgk5FCr1xqKLgtiHWPpypuCjGcn7BALtfheYpHJJ8xazm", // 105
    "72xkgSZti42Jrp3i3DH59T3j86spwfvddYGigEASYbtUHT5Un5D2i3DRzw2zBLZCPFer3QDktMdqATvu5WhSMd6c1Up9qZ6", // 106
    "7Bhe77jdbNM2GB3NWAfoVShP7XQBd5HV84wpmiNJjFsmNfACNvxVNehfQGgtRFN3a75ZZDt4FHzrNYCDv5rP1raWDTGxgmd", // 107
    "76giGYvE7cCfnY3mMuFM6K7TgDAjepuCDPfpz6MurW8LgNC6kfBPsFB3bapxG3Lbrg5zUc1NfT331QiLgee9Q2iRQLCh3VS", // 108
    "75QxVeKZgMUJa1PUuFj4LxZoTumLFeNMySAqQfhCJ8aJKDL6viArMUhGEhJaN7i3VVBDgJ8iW3mf6Bbn6TYLinYR7vwtHdb", // 109
];
const SUB1: &str = SUBS[0];
const SUB2: &str = SUBS[1];
const SUB3: &str = SUBS[2];
const INTEGRATED: &str = "5FHmhNWouJ76EzvernZJBcPXiZym13w1CfbpDU6sR8aSGpaRbAmU4EMSH3XYXu5U1cSac7B49WRSSBbwQK9by3c7R3PDbmJGUNm7bwo6K9";
const MAIN_SUB: &str = "8AH28DTbc3cYwUv6YZeq9ujTNWvrMyMxXaJaDt9yEpnTLiQpBfYssq4PNxMJywinEignsaB5jkfgNeSQFgsoyPn2CW7kmSL";
const SIG: &str = "SigV2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(PgPoolOptions::new().max_connections(8).connect(&url).await.expect("DATABASE_URL is set but the database is unreachable"))
}

fn cfg() -> PaymentConfig {
    PaymentConfig::defaults("vespiary-market")
}

fn uniq() -> String {
    app::sessions::new_token()[..16].to_string()
}

async fn make_account(pool: &PgPool, role: &str) -> (i64, String) {
    let public_id = app::db::public_id("acct_");
    let username = format!("pay{}", uniq());
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at)
         VALUES ($1, $2, 'x', $3, now() - interval '72 hours') RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, public_id)
}

async fn install_key(pool: &PgPool, account_id: i64) {
    let fpr = format!("{:040X}", rand::random::<u128>() % (1u128 << 127));
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status)
         VALUES ($1, $2, $3, 1, 'current')",
    )
    .bind(account_id)
    .bind(b"payments-test-dummy-cert".to_vec())
    .bind(&fpr)
    .execute(pool)
    .await
    .unwrap();
}

async fn make_listing(pool: &PgPool, seller_id: i64) -> String {
    let public_id = app::db::public_id("lst_");
    sqlx::query(
        "INSERT INTO listings (public_id, seller_id, title, description, price_atomic,
            pricing_module, destination_module, auto_invoice, status, category)
         VALUES ($1, $2, 'Pay Widget', 'A widget.', 1250000000000, 'xmr-only',
                 'signed-address-pool', false, 'published', 'general')",
    )
    .bind(&public_id)
    .bind(seller_id)
    .execute(pool)
    .await
    .unwrap();
    public_id
}

fn batch_json(cfg: &PaymentConfig, seller_pub: &str, primary: &str, subs: &[&str]) -> String {
    let seller_id = payment_seller_id(seller_pub).unwrap();
    let entries: Vec<serde_json::Value> = subs
        .iter()
        .map(|s| {
            serde_json::json!({
                "subaddress": s,
                "message": canonical_message(&cfg.marketplace_id, cfg.network, &seller_id, primary, s),
                "signature": SIG,
            })
        })
        .collect();
    serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": cfg.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_id,
        "primary_address": primary,
        "entries": entries,
    })
    .to_string()
}

/// A seller with key, listing, payment identity, and an uploaded pool.
async fn shop_with_pool(pool: &PgPool, subs: &[&str]) -> (i64, String, String) {
    let (seller_id, seller_pub) = make_account(pool, "seller").await;
    install_key(pool, seller_id).await;
    let listing = make_listing(pool, seller_id).await;
    let c = cfg();
    set_primary_address(pool, seller_id, PRIMARY_A, &c).await.unwrap();
    upload_batch(pool, seller_id, &batch_json(&c, &seller_pub, PRIMARY_A, subs), &c)
        .await
        .unwrap();
    (seller_id, seller_pub, listing)
}

async fn cleanup(pool: &PgPool, accounts: &[i64]) {
    for id in accounts {
        for q in [
            "DELETE FROM payment_attestations WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM reputation_facts WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = $1 OR seller_id = $1)",
            "DELETE FROM reputation_summaries WHERE seller_id = $1",
            "DELETE FROM payment_pool_entries WHERE seller_id = $1",
            "DELETE FROM payment_batches WHERE seller_id = $1",
            "DELETE FROM payment_identities WHERE seller_id = $1",
            "DELETE FROM destinations WHERE seller_id = $1",
            "DELETE FROM notifications WHERE account_id = $1",
            "DELETE FROM orders WHERE buyer_id = $1 OR seller_id = $1",
            "DELETE FROM listings WHERE seller_id = $1",
            "DELETE FROM identity_keys WHERE account_id = $1",
            "DELETE FROM accounts WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.unwrap();
        }
    }
}

/// The global `destinations` table is shared with the locked blind
/// suites, which pre-clean their fixture slices but leave their final
/// state in the DB. These fixture addresses come from the same
/// POOL200 set, so purge any stale rows for them before each test —
/// the same pre-clean discipline the blind suite uses — making this
/// suite re-runnable against a dirty dev DB.
static FIXTURE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn fixture_lock() -> &'static tokio::sync::Mutex<()> {
    FIXTURE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn purge_fixture_addresses(pool: &PgPool) {
    let owned: Vec<String> = SUBS.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "DELETE FROM payment_attestations WHERE pool_entry_id IN \
         (SELECT id FROM payment_pool_entries WHERE address = ANY($1))",
    )
    .bind(&owned).execute(pool).await.expect("purge attestations");
    sqlx::query("DELETE FROM payment_pool_entries WHERE address = ANY($1)")
        .bind(&owned).execute(pool).await.expect("purge entries");
    sqlx::query("DELETE FROM destinations WHERE address = ANY($1)")
        .bind(&owned).execute(pool).await.expect("purge destinations");
}

#[tokio::test]
async fn batch_validation_rejections_are_all_or_nothing() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    set_primary_address(&pool, seller_id, PRIMARY_A, &c).await.unwrap();
    let good = batch_json(&c, &seller_pub, PRIMARY_A, &[SUB1, SUB2]);

    // Wrong seller_id.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["seller_id"] = "acct-00000000000000000000000000000000".into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::WrongSeller));
    // Wrong network.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["network"] = "mainnet".into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::WrongNetwork));
    // Wrong marketplace_id.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["marketplace_id"] = "other-market".into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::WrongMarketplace));
    // Wrong primary address.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["primary_address"] = PRIMARY_B.into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::WrongPrimary));
    // Wrong format string.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    v["format"] = "xmr-direct-batch-v2".into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::WrongFormat));
    // Canonical rebuild mismatch: one byte changed in one message.
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    let mut msg = v["entries"][0]["message"].as_str().unwrap().to_string();
    msg.push('x');
    v["entries"][0]["message"] = msg.into();
    assert_eq!(upload_batch(&pool, seller_id, &v.to_string(), &c).await, Err(PaymentError::MessageMismatch));
    // Standard address where a subaddress belongs.
    let bad = batch_json(&c, &seller_pub, PRIMARY_A, &[PRIMARY_B]);
    assert!(matches!(upload_batch(&pool, seller_id, &bad, &c).await, Err(PaymentError::BadSubaddress(_))));
    // Integrated address where a subaddress belongs.
    let bad = batch_json(&c, &seller_pub, PRIMARY_A, &[INTEGRATED]);
    assert!(matches!(upload_batch(&pool, seller_id, &bad, &c).await, Err(PaymentError::BadSubaddress(_))));
    // Mainnet subaddress on a stagenet instance.
    let bad = batch_json(&c, &seller_pub, PRIMARY_A, &[MAIN_SUB]);
    assert!(matches!(upload_batch(&pool, seller_id, &bad, &c).await, Err(PaymentError::BadSubaddress(_))));
    // Duplicate inside the batch.
    let dup = batch_json(&c, &seller_pub, PRIMARY_A, &[SUB3, SUB3]);
    assert_eq!(upload_batch(&pool, seller_id, &dup, &c).await, Err(PaymentError::DuplicateAddress));
    // Nothing was stored by any rejection.
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 0);
    // The good batch lands; a second upload of an existing address is a
    // global duplicate (any seller, any state).
    assert_eq!(upload_batch(&pool, seller_id, &good, &c).await.unwrap(), 2);
    let again = batch_json(&c, &seller_pub, PRIMARY_A, &[SUB1]);
    assert_eq!(upload_batch(&pool, seller_id, &again, &c).await, Err(PaymentError::DuplicateAddress));
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 2);
    cleanup(&pool, &[seller_id]).await;
}

#[tokio::test]
async fn batch_size_and_pool_limits() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    let mut small = cfg();
    small.max_batch = 2;
    small.max_unused_pool = 3;
    set_primary_address(&pool, seller_id, PRIMARY_A, &small).await.unwrap();
    let three = batch_json(&small, &seller_pub, PRIMARY_A, &[SUBS[10], SUBS[11], SUBS[12]]);
    assert_eq!(upload_batch(&pool, seller_id, &three, &small).await, Err(PaymentError::BatchTooLarge));
    let two = batch_json(&small, &seller_pub, PRIMARY_A, &[SUBS[10], SUBS[11]]);
    assert_eq!(upload_batch(&pool, seller_id, &two, &small).await.unwrap(), 2);
    let two_more = batch_json(&small, &seller_pub, PRIMARY_A, &[SUBS[13], SUBS[14]]);
    assert_eq!(upload_batch(&pool, seller_id, &two_more, &small).await, Err(PaymentError::PoolFull));
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 2);
    cleanup(&pool, &[seller_id]).await;
}

#[tokio::test]
async fn allocation_concurrency_takes_different_entries() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[20], SUBS[21], SUBS[22]]).await;
    let (buyer1, _) = make_account(&pool, "buyer").await;
    let (buyer2, _) = make_account(&pool, "buyer").await;
    let (p1, p2) = (pool.clone(), pool.clone());
    let (l1, l2) = (listing.clone(), listing.clone());
    let (c1, c2) = (c.clone(), c.clone());
    let h1 = tokio::spawn(async move {
        create_order_with_config(&p1, "vespiary-market", buyer1, &l1, 1, "conc-1", &c1).await
    });
    let h2 = tokio::spawn(async move {
        create_order_with_config(&p2, "vespiary-market", buyer2, &l2, 1, "conc-2", &c2).await
    });
    let (o1, _) = h1.await.unwrap().unwrap();
    let (o2, _) = h2.await.unwrap().unwrap();
    let a1 = assignment_for_order(&pool, o1.id, &c).await.unwrap().unwrap();
    let a2 = assignment_for_order(&pool, o2.id, &c).await.unwrap().unwrap();
    assert_ne!(a1.address, a2.address, "concurrent orders must take different subaddresses");
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 1);
    cleanup(&pool, &[seller_id, buyer1, buyer2]).await;
}

#[tokio::test]
async fn cancel_retires_entry_and_next_order_gets_a_fresh_one() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[30], SUBS[31]]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (o1, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "cr-1", &c).await.unwrap();
    let a1 = assignment_for_order(&pool, o1.id, &c).await.unwrap().unwrap();
    apply_action(&pool, &o1, "cancel", buyer).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM payment_pool_entries WHERE id = $1")
        .bind(a1.entry_id).fetch_one(&pool).await.unwrap();
    assert_eq!(state, "retired");
    let (o2, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "cr-2", &c).await.unwrap();
    let a2 = assignment_for_order(&pool, o2.id, &c).await.unwrap().unwrap();
    assert_ne!(a1.address, a2.address, "cancelled order's address must never be reused");
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn pool_empty_refuses_and_no_identity_keeps_legacy_behaviour() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    // Identity + exactly one address: first order takes it, second is refused.
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[40]]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "pe-1", &c).await.unwrap();
    let err = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "pe-2", &c)
        .await
        .expect_err("empty pool must refuse creation");
    assert_eq!(err, OrderError::PoolEmpty);
    // No payment identity at all: order proceeds with no assignment.
    let (plain_seller, _) = make_account(&pool, "seller").await;
    install_key(&pool, plain_seller).await;
    let plain_listing = make_listing(&pool, plain_seller).await;
    let (o, created) = create_order_with_config(&pool, "vespiary-market", buyer, &plain_listing, 1, "pe-3", &c).await.unwrap();
    assert!(created);
    assert!(assignment_for_order(&pool, o.id, &c).await.unwrap().is_none());
    // Accept on that legacy order no longer meets the Stage 4 invoice
    // gate — it was removed by the BL1 amendment (2026-10-19): nothing
    // issues invoices, so the gate made assignment-less orders
    // unacceptable forever. Accept succeeds into AwaitingPayment, but
    // no payment path opens: mark_paid refuses the unassigned order
    // with NoAssignment.
    let state = apply_action(&pool, &o, "accept", plain_seller).await.expect("legacy accept must succeed since the BL1 amendment");
    assert_eq!(format!("{state:?}"), "AwaitingPayment");
    let o = app::orders::order_by_public_id(&pool, &o.public_id).await.unwrap();
    let err = mark_paid(&pool, &o, plain_seller, &c).await.expect_err("mark_paid without an assignment must refuse");
    assert_eq!(err, PaymentError::NoAssignment);
    cleanup(&pool, &[seller_id, plain_seller, buyer]).await;
}

#[tokio::test]
async fn mark_paid_authorization_and_attestation_record() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[50], SUBS[51]]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "mp-1", &c).await.unwrap();
    // Too early: still Requested.
    assert_eq!(mark_paid(&pool, &order, seller_id, &c).await, Err(PaymentError::NotAwaitingPayment));
    // Seller accepts — the assignment satisfies the accept gate.
    apply_action(&pool, &order, "accept", seller_id).await.unwrap();
    let order = app::orders::order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(order.state, "AwaitingPayment");
    // The buyer cannot mark paid.
    assert_eq!(mark_paid(&pool, &order, buyer, &c).await, Err(PaymentError::NotSeller));
    // A third party cannot either.
    let (stranger, _) = make_account(&pool, "buyer").await;
    assert_eq!(mark_paid(&pool, &order, stranger, &c).await, Err(PaymentError::NotSeller));
    // The seller can, exactly once.
    mark_paid(&pool, &order, seller_id, &c).await.unwrap();
    let order = app::orders::order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(order.state, "Paid");
    assert_eq!(order.evidence_level, "SellerAttested");
    assert_eq!(mark_paid(&pool, &order, seller_id, &c).await, Err(PaymentError::NotAwaitingPayment));
    // Attestation recorded with NO amount (hard rule: never amounts).
    let (kind, amount): (String, Option<i64>) = sqlx::query_as(
        "SELECT claim_kind, amount_atomic FROM payment_attestations WHERE order_id = $1",
    )
    .bind(order.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind, "seller-attestation");
    assert_eq!(amount, None);
    cleanup(&pool, &[seller_id, buyer, stranger]).await;
}

#[tokio::test]
async fn payment_assignment_round_trips_byte_exact() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    install_key(&pool, seller_id).await;
    let listing = make_listing(&pool, seller_id).await;
    set_primary_address(&pool, seller_id, PRIMARY_A, &c).await.unwrap();
    // A distinctive signature, stored verbatim.
    let seller_pid = payment_seller_id(&seller_pub).unwrap();
    let message = canonical_message(&c.marketplace_id, c.network, &seller_pid, PRIMARY_A, SUBS[60]);
    let signature = "SigV2-byte-exact_CHECK.123";
    let batch = serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": c.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_pid,
        "primary_address": PRIMARY_A,
        "entries": [{ "subaddress": SUBS[60], "message": message, "signature": signature }],
    })
    .to_string();
    upload_batch(&pool, seller_id, &batch, &c).await.unwrap();
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "be-1", &c).await.unwrap();
    // Exactly what the payment page renders: byte-for-byte what was uploaded.
    let a = assignment_for_order(&pool, order.id, &c).await.unwrap().unwrap();
    assert_eq!(a.address, SUBS[60]);
    assert_eq!(a.message, message);
    assert_eq!(a.signature, signature);
    assert_eq!(a.primary_address, PRIMARY_A);
    assert!(a.identity_changed_at.is_none(), "first set shows no change banner");
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn primary_change_retires_pool_and_shows_banner() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _pub, _listing) = shop_with_pool(&pool, &[SUBS[70], SUBS[71]]).await;
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 2);
    set_primary_address(&pool, seller_id, PRIMARY_B, &c).await.unwrap();
    assert_eq!(unused_count(&pool, seller_id).await.unwrap(), 0, "change retires all unused entries");
    let identity = app::payments::get_identity(&pool, seller_id).await.unwrap().unwrap();
    assert_eq!(identity.primary_address, PRIMARY_B);
    assert!(identity.changed_at.is_some());
    let banner = app::payments::identity_changed_recently(&pool, seller_id, &c).await.unwrap();
    assert!(banner.is_some(), "change banner shows inside the warning window");
    // Re-setting the same address is a no-op (no new change stamp).
    set_primary_address(&pool, seller_id, PRIMARY_B, &c).await.unwrap();
    // Wrong-kind / wrong-network primaries are rejected.
    assert!(matches!(
        set_primary_address(&pool, seller_id, SUBS[72], &c).await,
        Err(PaymentError::BadPrimary(_))
    ));
    cleanup(&pool, &[seller_id]).await;
}

#[tokio::test]
async fn expiry_sweep_cancels_and_retires() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[80], SUBS[81]]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "ex-1", &c).await.unwrap();
    let a = assignment_for_order(&pool, order.id, &c).await.unwrap().unwrap();
    sqlx::query("UPDATE orders SET created_at = now() - interval '49 hours' WHERE id = $1")
        .bind(order.id).execute(&pool).await.unwrap();
    let n = expire_unpaid_orders(&pool, &c).await.unwrap();
    assert!(n >= 1);
    let after = app::orders::order_by_public_id(&pool, &order.public_id).await.unwrap();
    assert_eq!(after.state, "Cancelled");
    let state: String = sqlx::query_scalar("SELECT state FROM payment_pool_entries WHERE id = $1")
        .bind(a.entry_id).fetch_one(&pool).await.unwrap();
    assert_eq!(state, "retired");
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn drain_defences_count_only_assigned_orders() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let mut c = cfg();
    c.open_unpaid_cap = 2;
    let (seller_id, _pub, listing) = shop_with_pool(&pool, &[SUBS[90], SUBS[91], SUBS[92], SUBS[93]]).await;
    let (buyer, _) = make_account(&pool, "buyer").await;
    create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "dd-1", &c).await.unwrap();
    create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "dd-2", &c).await.unwrap();
    let err = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "dd-3", &c)
        .await
        .expect_err("third open unpaid assigned order must hit the cap");
    assert_eq!(err, OrderError::TooManyOpenUnpaid);
    cleanup(&pool, &[seller_id, buyer]).await;
}

#[tokio::test]
async fn assignment_primary_comes_from_the_signed_message() {
    let Some(pool) = pool().await else { return };
    let _fixture_guard = fixture_lock().lock().await;
    purge_fixture_addresses(&pool).await;
    let c = cfg();
    let (seller_id, seller_pub) = make_account(&pool, "seller").await;
    install_key(&pool, seller_id).await;
    let listing = make_listing(&pool, seller_id).await;
    set_primary_address(&pool, seller_id, PRIMARY_A, &c).await.unwrap();
    let seller_pid = payment_seller_id(&seller_pub).unwrap();
    let message = canonical_message(&c.marketplace_id, c.network, &seller_pid, PRIMARY_A, SUBS[61]);
    let batch = serde_json::json!({
        "format": "xmr-direct-batch-v1",
        "marketplace_id": c.marketplace_id,
        "network": "stagenet",
        "seller_id": seller_pid,
        "primary_address": PRIMARY_A,
        "entries": [{ "subaddress": SUBS[61], "message": message, "signature": "SigV2-assignment-primary" }],
    })
    .to_string();
    upload_batch(&pool, seller_id, &batch, &c).await.unwrap();
    let (buyer, _) = make_account(&pool, "buyer").await;
    let (order, _) = create_order_with_config(&pool, "vespiary-market", buyer, &listing, 1, "ap-1", &c).await.unwrap();
    // Seller changes payment identity AFTER the order was assigned.
    let changed = set_primary_address(&pool, seller_id, PRIMARY_B, &c).await.unwrap();
    assert!(changed);
    // The assignment still names the primary whose key signed the
    // message — that is the address the buyer pastes into their wallet
    // to verify, so it must not silently track the new identity.
    let a = assignment_for_order(&pool, order.id, &c).await.unwrap().unwrap();
    assert_eq!(a.primary_address, PRIMARY_A);
    assert_eq!(a.message, message);
    cleanup(&pool, &[seller_id, buyer]).await;
}
