// Copyright 2021-2023 Protocol Labs
// SPDX-License-Identifier: Apache-2.0, MIT
use fvm::call_manager::CallManager;
use fvm::gas::Gas;
use fvm::kernel::prelude::*;
use fvm::kernel::Result;
use fvm::kernel::{
    ActorOps, CryptoOps, DebugOps, EventOps, IpldBlockOps, MessageOps, NetworkOps, RandomnessOps,
    SelfOps, SendOps, SyscallHandler, UpgradeOps,
};
use fvm::syscalls::Linker;
use fvm::DefaultKernel;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::randomness::RANDOMNESS_LENGTH;
use fvm_shared::sys::out::network::NetworkContext;
use fvm_shared::sys::out::vm::MessageContext;
use fvm_shared::{address::Address, econ::TokenAmount, ActorID, MethodNum};

use ambassador::Delegate;
use cid::Cid;

// Used for fheid custome syscalls
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use tfhe::{FheUint32, set_server_key, CompressedServerKey, CompactFheUint32};
use std::str;
use tfhe::prelude::*;
use std::fs;

// we define a single custom syscall which simply doubles the input
pub trait CustomKernel: Kernel {
    fn fheid_custom_syscall(&self) -> anyhow::Result<()>;
}

// our custom kernel extends the filecoin kernel
#[derive(Delegate)]
#[delegate(IpldBlockOps, where = "C: CallManager")]
#[delegate(ActorOps, where = "C: CallManager")]
#[delegate(CryptoOps, where = "C: CallManager")]
#[delegate(DebugOps, where = "C: CallManager")]
#[delegate(EventOps, where = "C: CallManager")]
#[delegate(MessageOps, where = "C: CallManager")]
#[delegate(NetworkOps, where = "C: CallManager")]
#[delegate(RandomnessOps, where = "C: CallManager")]
#[delegate(SelfOps, where = "C: CallManager")]
#[delegate(SendOps<K>, generics = "K", where = "K: CustomKernel")]
#[delegate(UpgradeOps<K>, generics = "K", where = "K: CustomKernel")]
pub struct CustomKernelImpl<C>(pub DefaultKernel<C>);

impl<C> CustomKernel for CustomKernelImpl<C>
where
    C: CallManager,
    CustomKernelImpl<C>: Kernel,
{
    fn fheid_custom_syscall(&self) -> anyhow::Result<()> {
    
        #[derive(Deserialize, Debug)]
        struct Fheid {
            server_key: Vec<u8>,
            birth_date: Vec<u8>,
            today_date: u32
        }

        let file = File::open("/home/ubuntu/myapp/src/encryptData.json")?;
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `Fheid`.
        let u: Fheid = serde_json::from_reader(reader).unwrap();

        // Read the JSON encrypted data from the file
        let server_key_bytes = u.server_key;
        let birthday_bytes = u.birth_date;

        //Deserialize the encrypted data
        let compressed_sks: CompressedServerKey = bincode::deserialize(&server_key_bytes).unwrap();
        let birthday: CompactFheUint32 = bincode::deserialize(&birthday_bytes).unwrap();
        let today: u32 = u.today_date;

        //Decompress and set server key for doing encrypted execution
        let sks = compressed_sks.decompress();
        set_server_key(sks);

        //Convert CompactFheUint32 to FheUint32 for doing encrypted calculations
        let birthday_fhe_uint32: FheUint32 = birthday.expand();
        let diff = today - birthday_fhe_uint32.clone();

        //Check if the person is an adult or not
        let encrypted_diff = &diff.gt(180000u32);

        //Serialize the result to return back to the client
        let encrypted_res_bytes: Vec<u8> = bincode::serialize(&encrypted_diff).unwrap();

        // Store encrypted result into the file 
        let s =format!("{:?}", &encrypted_res_bytes.as_slice());
        let string = String::from("./src/encrypted_res.txt");
        let path = Path::new(&string);
        fs::write(path, s).unwrap();

        Ok(())
    }
}

impl<C> Kernel for CustomKernelImpl<C>
where
    C: CallManager,
{
    type CallManager = C;
    type Limiter = <DefaultKernel<C> as Kernel>::Limiter;

    fn into_inner(self) -> (Self::CallManager, BlockRegistry)
    where
        Self: Sized,
    {
        self.0.into_inner()
    }

    fn new(
        mgr: C,
        blocks: BlockRegistry,
        caller: ActorID,
        actor_id: ActorID,
        method: MethodNum,
        value_received: TokenAmount,
        read_only: bool,
    ) -> Self {
        CustomKernelImpl(DefaultKernel::new(
            mgr,
            blocks,
            caller,
            actor_id,
            method,
            value_received,
            read_only,
        ))
    }

    fn machine(&self) -> &<Self::CallManager as CallManager>::Machine {
        self.0.machine()
    }

    fn limiter_mut(&mut self) -> &mut Self::Limiter {
        self.0.limiter_mut()
    }

    fn gas_available(&self) -> Gas {
        self.0.gas_available()
    }

    fn charge_gas(&self, name: &str, compute: Gas) -> Result<GasTimer> {
        self.0.charge_gas(name, compute)
    }
}

impl<K> SyscallHandler<K> for CustomKernelImpl<K::CallManager>
where
    K: CustomKernel
        + ActorOps
        + SendOps
        + UpgradeOps
        + IpldBlockOps
        + CryptoOps
        + DebugOps
        + EventOps
        + MessageOps
        + NetworkOps
        + RandomnessOps
        + SelfOps,
{
    fn link_syscalls(linker: &mut Linker<K>) -> anyhow::Result<()> {
        DefaultKernel::<K::CallManager>::link_syscalls(linker)?;

        linker.link_syscall("my_custom_kernel", "fheid_custom_syscall", fheid_custom_syscall)?;

        Ok(())
    }
}

pub fn fheid_custom_syscall(context: fvm::syscalls::Context<'_, impl CustomKernel>) -> anyhow::Result<()> {
    context.kernel.fheid_custom_syscall()
}