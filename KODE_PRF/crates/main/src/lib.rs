
use types::{
    BivariateDKGArgs, BivariateNiDKGArgs, BivariateShareFileArgs, BivariateThresholdSignatureArgs,
    NiDKGKeyPairsArgs, UnivariateDKGArgs, UnivariateNiDKGArgs, UnivariateShareFileArgs,
    UnivariateThresholdSignatureArgs,
};
use univariate_dkg as univariate;

pub async fn univariate_dkg(args: UnivariateDKGArgs) {
    univariate::api::run_local_dkg(args.node_index, args.num_nodes as u32, args.threshold).await;
}

pub async fn bivariate_dkg(args: BivariateDKGArgs) {
  
}

pub async fn univariate_nidkg(args: UnivariateNiDKGArgs) {

}

pub fn bivariate_nidkg(args: BivariateNiDKGArgs) {
    println!("TODO: Run bivariate ni dkg with args: {:?}", args);
}

pub fn generate_keypairs(args: NiDKGKeyPairsArgs) {
 
}

pub async fn univariate_threshold_signature(args: UnivariateThresholdSignatureArgs) {
    if !args.aws {
        univariate::api::run_local_threshold_signature(
            args.node_index,
            args.num_nodes_n as u32,
            args.threshold,
        )
        .await;
    } else {
        univariate::api::run_aws_threshold_signature(
            args.node_index,
            args.num_nodes_n as u32,
            args.threshold,
        )
        .await;
    }
}

pub async fn bivariate_threshold_signature(args: BivariateThresholdSignatureArgs) {
}

pub fn univariate_share_file(args: UnivariateShareFileArgs) {
    univariate::api::write_dealing_to_file(args.num_nodes as u32, args.threshold_t);
}

pub fn bivariate_share_file(args: BivariateShareFileArgs) {

}
