#[cfg(target_os = "illumos")]
mod illumos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "illumos")]
pub use illumos::*;

#[cfg(target_os = "linux")]
pub use linux::*;
