This is an attempt to re-write [SDHash](http://roussev.net/sdhash/sdhash.html) into Rust! Initially, I was thinking to use Rust's `bindgen`, but this SDHash source depends on OpenSSL, which I don't wish to add as a dependency.

This is an active work-in-progress, and has not been tested at all. I expect it to be riddled with bugs.

The copy of the SDHash C code in this project is not used by the Rust code, it's here as a reference as the code is translated into Rust. The goal is to re-implement the following features:
* File or byte array to SDHash
* SDHash to byte array
* Comparison of two SDHash values to get a similarity score.

At this time, it's not a goal to re-create the application (`main()`) component of this code, only the library part is (likely) going to be re-implemented.

The original code and concept is created by Vassil Roussev.