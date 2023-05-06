use mongodb::IndexModel;
use mongodb::options::{IndexOptions, AggregateOptions};
use mongodb::{Client, options::{ClientOptions, ResolverConfig}, bson::doc, Collection};
use bson::Document;
use futures::stream::TryStreamExt;

async fn mining_rule_with_fp_growth(data_path:&str,omega:f64,loaded_num:u64,scoring_rate:f64,obp_rate:f64,support_rate:f64)->Result<Vec<Vec<String>>>{
    // let data_path = "uop28.csv";
    //load csv
    // let  (mut transactions,mut para_space,mut uniqueSet) = load_csv(data_path,1000).expect("failed to load csv data");
    // let  (mut transactions,mut para_space,mut uniqueSet) = load_csv_to_mongodb(data_path,100000).await.expect("failed to load csv data");
    let  (mut transactions,mut uniqueSet) = load_csv_to_mongodb_with_scoring(data_path,loaded_num,scoring_rate,obp_rate).await.expect("failed to load csv data");
    println!("transaction len ={}",transactions.len());
    let  mutcount = 0;
    // for item in &para_space{
    //     ;
    // }
    let mut rule_vec :Vec<String>= Vec::new();
    let mut fs_rule_vec:Vec<FilesystemRule> = Vec::new();
    let mut rule_set_str = Vec::new();
    // let mut pattern_over_rate = HashMap::new();

    let client = Client::with_uri_str("mongodb://localhost").await.expect("failed to connect mongodb");
    let transaction_original:Collection<Document> = client.database("esx_mining").collection("transacation_original");
    let transaction_original_distinct:Collection<Document> = client.database("esx_mining").collection("transacation_distinct");
    let gid_collection:Collection<Document> = client.database("esx_mining").collection("para_space_gid");
    // 存储overate相关信息的collection
    let overate_collection:Collection<Document> = client.database("esx_mining").collection(("overate_".to_string()+loaded_num.to_string().as_str()).as_str());

    let para_space_size = client.database("esx_mining").collection::<Document>("para_space_original").estimated_document_count(None).await.expect("failed to connect para space data in mongo");
    let mut gids_cur = gid_collection.find(None, None).await.unwrap();
    let mut gids_vec:Vec<String> = Vec::new();

    while let Some(gid_doc) = gids_cur.try_next().await? {

        let gid = gid_doc.get("gid").unwrap().to_string().replace("\"", "");
        gids_vec.push(gid.clone());
    }
    let mut para_space_size =0;
    for gid in &gids_vec{
        let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid.clone().as_str()).as_str());
        let para_tmp = giddb.estimated_document_count(None).await.unwrap();
        para_space_size = para_space_size + para_tmp;
    }
    println!("para space size:{}",para_space_size.clone());
    let start_time = SystemTime::now();
    while !&transactions.is_empty()  {
        let mut transactions_for_fp = Vec::new();
        for single_vec_transaction in &transactions {
            let mut single_vec_for_fp = Vec::new();
            for single_com_transaction in single_vec_transaction {
                single_vec_for_fp.push(single_com_transaction.as_str());
            }
            transactions_for_fp.push(single_vec_for_fp);
        }
        let trans_len = transactions.len().clone();
        if trans_len == 0 as usize{
            break;
        }
        let mut minimum_support = (support_rate*trans_len.clone()as f64) as usize;
        // if trans_len.clone()<100{
        //     minimum_support = 1;
        // }

        let fp_growth_str = FPGrowth::new(transactions_for_fp.clone(), minimum_support);
        let mut result = fp_growth_str.find_frequent_patterns();

        println!("The number of results: {}", result.frequent_patterns_num());
        if result.frequent_patterns_num() == 0{
            minimum_support = 1;
            let fp_growth_str = FPGrowth::new(transactions_for_fp, minimum_support);
            result = fp_growth_str.find_frequent_patterns();
        }
        let mut max_support: usize = 0;
        let mut max_c_score =NEG_INFINITY;
        let mut most_frequent_pattern: Vec<&str> = Vec::new();
        let pattern_len =result.frequent_patterns().len().clone();
        let pb = ProgressBar::new(pattern_len.clone() as u64);
        // let mut influence_tmp = vec![];
        // let mut para_space_size = 0;
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}({per_sec},{eta})")
            .unwrap()
            .progress_chars("#>-"));
        let mut frequent_pattern_to_calculate = 0;
        // let calculation_limit = 40;
        for (frequent_pattern, support) in result.frequent_patterns().iter() {
            pb.inc(1);
            let len = &frequent_pattern.len();

            if frequent_pattern.contains(&"logtype:FILE") || frequent_pattern.contains(&"logtype:NET") {

                // 防止过多的计算
                // if frequent_pattern_to_calculate >= calculation_limit {
                //     break;
                // }
                frequent_pattern_to_calculate = frequent_pattern_to_calculate + 1;


                let frequent_pattern_tmp = frequent_pattern.clone();
                let log_entries_len = trans_len.clone();
                // let (coverage_rate_fn,unique_logs_count,cover_logs_count) = calculating_coverage_rate(&transactions,&most_frequent_pattern).expect("failed to calculate coverage rate");
                let (coverage_rate_fn,unique_logs_count,cover_logs_count) = calculating_coverage_rate_mongo(&frequent_pattern_tmp).await.expect("failed to calculate coverage rate");

                let (mut influence_rate_from_space, mut unique_space_count) =(0.0,0);

                if frequent_pattern_tmp.contains(&"logtype:FILE") {
                    let rule_tmp = generate_fsrule_from_item(&frequent_pattern_tmp).unwrap();
                    let op_overate = overate_collection.find_one(doc!{
                        "pattern":rule_tmp.to_string()
                    }, None).await.unwrap();
                    match op_overate {
                        Some(op_tun) =>{
                            influence_rate_from_space = op_tun.get("influence_rate_from_space").unwrap().as_f64().unwrap();
                            unique_space_count = op_tun.get("unique_space_count").unwrap().as_i32().unwrap() as usize;
                        }
                        None=>{
                            (influence_rate_from_space,unique_space_count) = calculating_overate_rate_mongo(&frequent_pattern_tmp,para_space_size as f64).await.expect("failed to calculate overate");
                            overate_collection.insert_one(doc!{
                                "pattern":rule_tmp.to_string(),
                                "influence_rate_from_space":influence_rate_from_space,
                                "unique_space_count":unique_space_count as i32
                            }, None).await.unwrap();
                        }
                    }
                    // let op_overate = pattern_over_rate.get(&*rule_tmp.create_influence_vec());
                    // influence_tmp = rule_tmp.create_influence_vec();
                    // match op_overate {
                    //     Some(op_tun)=>{
                    //         (influence_rate_from_space,unique_space_count) = *op_tun;
                    //     }
                    //     None => {
                    //         (influence_rate_from_space,unique_space_count) = calculating_overate_rate_mongo(&frequent_pattern_tmp,para_space_size as f64).await.expect("failed to calculate overate");
                    //         // (influence_rate_from_space,unique_space_count) = calculating_over_rate(&para_space,&most_frequent_pattern).expect("failed to calculate overate");
                    //         pattern_over_rate.insert(rule_tmp.create_influence_vec(),(influence_rate_from_space,unique_space_count));
                    //     }

                    // }
                }
                else if frequent_pattern_tmp.contains(&"logtype:NET") {
                    let rule_tmp = generate_netrule_from_item(&frequent_pattern_tmp).unwrap();
                    let op_overate = overate_collection.find_one(doc!{
                        "pattern":rule_tmp.to_string()
                    }, None).await.unwrap();
                    match op_overate {
                        Some(op_tun) =>{
                            influence_rate_from_space = op_tun.get("influence_rate_from_space").unwrap().as_f64().unwrap();
                            unique_space_count = op_tun.get("unique_space_count").unwrap().as_i32().unwrap() as usize;
                        }
                        None=>{
                            (influence_rate_from_space,unique_space_count) = calculating_overate_rate_mongo(&frequent_pattern_tmp,para_space_size as f64).await.expect("failed to calculate overate");
                            overate_collection.insert_one(doc!{
                                "pattern":rule_tmp.to_string(),
                                "influence_rate_from_space":influence_rate_from_space,
                                "unique_space_count":unique_space_count as i32
                            }, None).await.unwrap();
                        }
                    }
                    // let op_overate = pattern_over_rate.get(&*rule_tmp.create_influence_vec());
                    // influence_tmp = rule_tmp.create_influence_vec();
                    // match op_overate {
                    //     Some(op_tun)=>{
                    //         (influence_rate_from_space,unique_space_count) = *op_tun;
                    //     }
                    //     None => {
                    //         // (influence_rate_from_space,unique_space_count) = calculating_over_rate(&para_space,&most_frequent_pattern).expect("failed to calculate overate");
                    //         (influence_rate_from_space,unique_space_count) = calculating_overate_rate_mongo(&frequent_pattern_tmp,para_space_size as f64).await.expect("failed to calculate overate");
                    //         pattern_over_rate.insert(rule_tmp.create_influence_vec(),(influence_rate_from_space,unique_space_count));
                    //     }
                    // }
                }else {
                    continue;
                }

                // let (influence_rate_from_space,unique_space_count) = calculating_over_rate(&para_space,&most_frequent_pattern).expect("failed to calculate overate");
                let overate = (unique_space_count as f64-unique_logs_count as f64)/(para_space_size as f64);
                let overate_not_distinct = (unique_space_count as f64-cover_logs_count as f64)/(para_space_size as f64);

                let over_assignment_total = unique_space_count as f64-unique_logs_count as f64;
                // let omega = 0.5;
                let Qrul_count = (unique_logs_count as f64)*(1.0-((omega * over_assignment_total)/unique_logs_count as f64));

                let l_distance = 0.0-(log_entries_len as f64 - cover_logs_count)-(omega*over_assignment_total);
                let harmonic_mean = (1.0+(omega*omega)) * ((overate*coverage_rate_fn)/(((omega*omega)*overate)+coverage_rate_fn));

                let Qrul_freq = (log_entries_len as f64 )*(1.0-((omega*over_assignment_total)/unique_logs_count as f64));
                let e_score = coverage_rate_fn + omega * (1.0-overate)+ omega * (1.0-overate_not_distinct);
                let C_scores = (cover_logs_count as f64 / log_entries_len as f64) + omega*(1.0-overate_not_distinct);
                // let c_score = l_distance;
                let c_score = e_score;
                println!("frequent pattern:{:?} ,influence rate: {} , overate :{},overate_n_d:{} ,c_score:{}",&frequent_pattern,coverage_rate_fn,overate,overate_not_distinct,c_score);

                if c_score>max_c_score {
                    max_c_score = c_score;
                    most_frequent_pattern = frequent_pattern.clone();
                    max_support = *support;
                }
            }
            // println!("{:?} {}", frequent_pattern, support);
        }
        pb.finish_and_clear();
        println!("most frequent:{:?} , max support={},max c_score={}", most_frequent_pattern, max_support,max_c_score);

        //做GC
        // let ret = pattern_over_rate.remove(&influence_tmp);


        let mut transacation_back = transactions.clone();
        let trans_len = &transactions.len();



        // let (coverage_rate_fn,unique_logs_count,cover_logs_count) = calculating_coverage_rate(&transactions,&most_frequent_pattern).expect("failed to calculate coverage rate");
        // let (influence_rate_from_space,unique_space_count,cover_space_count) = calculating_coverage_rate(&para_space,&most_frequent_pattern).expect("failed to calculate overate");
        // let overate = (unique_space_count as f64-unique_logs_count as f64)/(para_space.len() as f64);
        let trans_after_delete =  delete_logs_from_rule(&most_frequent_pattern).await.unwrap();

        if most_frequent_pattern.contains(&"logtype:FILE"){
            let fsrule = generate_fsrule_from_item(&most_frequent_pattern).unwrap();
            rule_set_str.push(fsrule.create_influence_vec());
        }else if most_frequent_pattern.contains(&"logtype:NET") {
            let netrule = generate_netrule_from_item(&most_frequent_pattern).unwrap();
            rule_set_str.push(netrule.create_influence_vec());
        }else{
            continue;
        }




        transacation_back = trans_after_delete;
        let len_after_delete = &transacation_back.len();
        println!("len of trans:{},len of back:{}", &trans_len.borrow(), len_after_delete);
        let end_time = SystemTime::now().duration_since(start_time).unwrap().as_secs_f64();
        println!("single mining time use:{}",end_time);
        // let converage_rate = (*trans_len as f64-*len_after_delete as f64)/(*trans_len as f64);
        // println!("coverage_rate = :{} coverage_rate_fn = {},overate ={}",converage_rate,coverage_rate_fn,overate);

        transactions = transacation_back;
    }
    println!("length of policy = {},rule set = {:?}",rule_set_str.len(),rule_set_str.clone());
    Ok(rule_set_str)
}
async fn calculating_overate_rate_mongo(frequent_pattern:&Vec<&str>,para_space_len:f64) -> Result<(f64,usize)>{
    let start_time = SystemTime::now();
    let client = Client::with_uri_str("mongodb://localhost").await.expect("failed to connect mongodb");
    // let para_space:Collection<Document> = client.database("esx_mining").collection("para_space_original");
    let gid_collection:Collection<Document> = client.database("esx_mining").collection("para_space_gid");

    let mut cover_logs_count = 0.0;
    let mut unique_cover_logs_count:usize =0;
    let mut transactions_count:f64 = 0.0;
    let mut over_rate = 0.0;
    let mut query_doc = doc!{};
    let mut gid_created_by_pattern = "".to_string();

    // transactions_count = para_space.count_documents(None, None).await.unwrap() as f64;
    if frequent_pattern.contains(&"logtype:FILE") {
        let fsrule = generate_fsrule_from_item(&frequent_pattern).unwrap();
        query_doc = fsrule.to_mongodb_doc();
        gid_created_by_pattern = fsrule.get_gid_string();

    } else if frequent_pattern.contains(&"logtype:NET"){
        let netrule = generate_netrule_from_item(&frequent_pattern).unwrap();
        query_doc = netrule.to_mongodb_doc();
        gid_created_by_pattern = netrule.get_gid_string();
    }
    // gid_created_by_pattern = query_doc.get("gid").unwrap().to_string();

    // cover_logs_count = para_space.count_documents(query_doc.clone(), None).await.unwrap() as f64;

    let mut gids_cur = gid_collection.find(None, None).await.unwrap();
    let mut gids_vec:Vec<String> = Vec::new();
    let mut cover_logs_count2 = 0;
    let mut cover_logs_count3 = 0;
    // let mut para_space_len = 0;
    while let Some(gid_doc) = gids_cur.try_next().await? {
        // let doc: YearSummary = bson::from_document(single_movie?)?;
        // movie_vec.push(single_movie.clone());
        let gid = gid_doc.get("gid").unwrap().to_string().replace("\"", "");
        // let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid.clone().as_str()).as_str());
        gids_vec.push(gid.clone());
        // println!("{:?}",gid_doc.get("gid").unwrap().to_string());
        // println!("found or* {}", single_year.get("_id").unwrap().as_document().unwrap().get("title").unwrap());
    }

    if gids_vec.contains(&gid_created_by_pattern){
        let start_time_find = SystemTime::now();
        //分表后，仅需要查询对应表

        let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid_created_by_pattern.clone().as_str()).as_str());
        cover_logs_count2 = giddb.count_documents(query_doc.clone(), None).await.unwrap();
        let find_time = SystemTime::now().duration_since(start_time_find).unwrap().as_secs_f64();
        let find_time_t = SystemTime::now();
        // println!("collection:{} find end,time use:{},coverlogs_count3:{}",("para_".to_owned()+gid_created_by_pattern.clone().as_str()).as_str(),find_time,cover_logs_count2);
        // for gid in &gids_vec{
        //     let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid.clone().as_str()).as_str());
        //     let para_tmp = giddb.estimated_document_count(None).await.unwrap();
        //     para_space_len = para_space_len + para_tmp;
        // }

        // println!("para len calculation time use:{}",SystemTime::now().duration_since(find_time_t).unwrap().as_secs_f64());




    } else{
        for gid in &gids_vec{
            let start_time_find = SystemTime::now();
            // println!("db name:{}",("para_".to_owned()+gid.clone().as_str()).as_str());
            let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid.clone().as_str()).as_str());
            let cover_logs_tmp = giddb.count_documents(query_doc.clone(), None).await.unwrap();
            cover_logs_count2 = cover_logs_count2 + cover_logs_tmp;

            let find_time = SystemTime::now().duration_since(start_time_find).unwrap().as_secs_f64();
            let find_time_t = SystemTime::now();
            // println!("collection:{} find end,time use:{}",("para_".to_owned()+gid.clone().as_str()).as_str(),find_time);
        }
        let end_time = SystemTime::now().duration_since(start_time).unwrap().as_secs_f64();
        // let start_time2 = SystemTime::now();
        // let count_mutex_u64:Arc<Mutex<u64>> = Arc::new(Mutex::new(0 as u64));
        // for gid in &gids_vec{
        //     let start_time_find = SystemTime::now();
        //     // println!("db name:{}",("para_".to_owned()+gid.clone().as_str()).as_str());
        //     let giddb:Collection<Document> = client.database("esx_mining").collection(("para_".to_owned()+gid.clone().as_str()).as_str());
        //     let query_doc = query_doc.clone();
        //     let count_mutex_u64 = count_mutex_u64.clone();
        //     let handle = tokio::task::spawn(async move {get_cover_logs_from_collection(query_doc.clone(),  count_mutex_u64,giddb).await;});
        //     tokio::time::timeout(Duration::from_secs(100), handle).await??;

        // }
        // cover_logs_count3 = *count_mutex_u64.lock().unwrap();
        // let end_time2 = SystemTime::now().duration_since(start_time2).unwrap().as_secs_f64();
        // println!("over_rate time:{} s , cover_logs:{} , over_rate time:{} s,cover_logs2:{}",end_time,cover_logs_count2,end_time2,cover_logs_count3);
    }
    // let end_time = SystemTime::now().duration_since(start_time).unwrap().as_secs_f64();

    // let start_time2 = SystemTime::now();



    // let end_time2 = SystemTime::now().duration_since(start_time2).unwrap().as_secs_f64();




    // if transactions_count!=0.0{
    //     over_rate = cover_logs_count as f64 / transactions_count as f64;
    // }
    let mut over_rate2 = 0.0;
    if para_space_len !=0.0{
        over_rate2 = cover_logs_count2 as f64 / para_space_len as f64;
    }
    // println!("cover logs count1:{};count2:{},over_rate1:{};over_rate2:{}",cover_logs_count,cover_logs_count2,over_rate.clone(),over_rate2.clone());


    Ok((over_rate2,  cover_logs_count2 as usize))
}
//load csv to mongodb
//input: csv file path ,number of logs to load
//output: original transaction and original parameter space

async fn load_csv_to_mongodb_with_scoring(data_path:&str,loaded_num:u64,scoring_rate:f64,obp_rate:f64) -> Result<(Vec<Vec<String>>,HashSet<String>)> {
    let pb = ProgressBar::new(loaded_num);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}({per_sec},{eta})")
        .unwrap()
        .progress_chars("#>-"));
    let client = Client::with_uri_str("mongodb://localhost").await.expect("failed to connect mongodb");
    let transaction_original:Collection<Document> = client.database("esx_mining").collection("transacation_original");
    let transaction_original_distinct:Collection<Document> = client.database("esx_mining").collection("transacation_distinct");
    let transaction_original_backup:Collection<Document> = client.database("esx_mining").collection("transacation_original_backup");
    let transaction_original_distinct_backup:Collection<Document> = client.database("esx_mining").collection("transacation_distinct_backup");
    // client.database("esx_mining").run_command(command, selection_criteria)
    let transaction_scoring:Collection<Document> = client.database("esx_mining").collection("transacation_scoring");
    let transaction_scoring_distinct:Collection<Document> = client.database("esx_mining").collection("transacation_scoring_distinct");
    let length_of_OBP = (loaded_num as f64 * (1.0-scoring_rate)) as usize;
    let mut transactions:Vec<Vec<String>> = Vec::new();
    let mut unique_set = HashSet::new();
    let mut transactions_to_output = Vec::new();
    // transaction_original_backup.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
    println!("back 里的数据量:{}",transaction_original_backup.count_documents(None,None).await.unwrap());
    // let  (mut transactions,mut para_space,mut unique_set) = load_csv(data_path,loaded_num).expect("failed to load csv data");
    if transaction_original_backup.count_documents(None,None).await.unwrap() == loaded_num as u64 {
        //不需要重新导入数据的情况
        let transaction_docs;
        let transactions_vecs;
        let length_of_OBP_true = (length_of_OBP as f64 * obp_rate) as usize;
        //start load mongodb
        (transactions_vecs,transaction_docs,unique_set) = load_mongodb_to_vec().await.expect("failed to load csv data");
        transactions_to_output = transactions_vecs[..length_of_OBP_true].to_vec();
        //start insert original
        transaction_original.delete_many(doc!{}, None).await.expect("failed to delete data in mongodb");
        transaction_original.insert_many(transaction_docs[..length_of_OBP_true].to_vec(), None).await.unwrap();

        //start insert scoring
        transaction_scoring.delete_many(doc!{}, None).await.expect("failed to delete data in mongodb");
        transaction_scoring.insert_many(transaction_docs[length_of_OBP..].to_vec(), None).await.expect("failed to delete data in mongodb");


        // 古法遍历去重，非常慢
        // let pb = ProgressBar::new(length_of_OBP.clone() as u64);
        // pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}({per_sec},{eta})")
        //     .unwrap()
        //     .progress_chars("#>-"));
        // for single_transaction in transaction_docs[..length_of_OBP].to_vec(){
        //     pb.inc(1);
        //     if !transaction_docs_distinct_OBP.contains(&single_transaction){
        //         transaction_docs_distinct_OBP.push(single_transaction.clone());
        //     }
        // }
        // pb.finish_and_clear();
        // println!("distinct vec:{},transaction distinct mongo:{}",transaction_docs_distinct_OBP.len().clone(),transaction_original_distinct.estimated_document_count(None).await.unwrap());
        // println!("distinct vec:{},transaction distinct mongo:{}",transaction_docs_distinct_EXP.len().clone(),transaction_scoring_distinct.estimated_document_count(None).await.unwrap());



        let disk_use_opt = AggregateOptions::builder().allow_disk_use(true).build();
        //start to insert distinct of OBP
        transaction_original_distinct.delete_many(doc!{}, None).await.unwrap();
        let dedup_pipe_line = generate_distinct_logs("transacation_distinct");
        transaction_original.aggregate(dedup_pipe_line, disk_use_opt.clone()).await.expect("Failed to deduplicate");


        //start to insert distinct of EXP
        transaction_scoring_distinct.delete_many(doc!{}, None).await.unwrap();
        let dedup_pipe_line_scoring = generate_distinct_logs("transacation_scoring_distinct");
        transaction_scoring.aggregate(dedup_pipe_line_scoring, disk_use_opt.clone()).await.expect("Failed to deduplicate");



    }else {
        //需要重新导入数据的情况

        // transaction_original_backup.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
        // transaction_original_distinct_backup.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
        // (transactions, para_space,unique_set) = load_csv_by_shard(data_path,loaded_num).expect("failed to load csv data");
        (transactions, unique_set) = load_csv_with_para_and_backup_loaded(data_path, loaded_num, "transaction_backup").await.unwrap();
        println!("重新导入的数据长度为{}",transactions.len().clone());
        let transaction_whole_len = transactions.len().clone();
        if transaction_original.count_documents(None,None).await.unwrap() != transaction_whole_len.clone() as u64 {
            transaction_original.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
            transaction_original_distinct.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
            transaction_scoring.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
            transaction_scoring_distinct.delete_many(doc!{},None).await.expect("failed to delete existing data in mongodb");
            let mut doc_set = Vec::new();
            // let mut doc_set_distinct = Vec::new();
            let transfer_limit = 100000;
            let mut log_of_OBP_count:usize = 0;

            // insert transaction to mongo
            for transaction in &transactions{
                pb.inc(1);
                let new_doc = doc! {
                "uid": transaction[0].clone(),
                "gid": transaction[1].clone(),
                "logtype": transaction[2].clone(),
                "op": transaction[3].clone(),
                "res":transaction[4].clone()
                };
                doc_set.push(new_doc.clone());
                // if !doc_set_distinct.contains(new_doc.borrow()){
                //     doc_set_distinct.push(new_doc.clone());
                // }
                log_of_OBP_count = log_of_OBP_count + 1;
                if log_of_OBP_count < length_of_OBP {
                    if doc_set.len() >= transfer_limit {
                        transaction_original.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_original_distinct.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_original_backup.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_original_distinct_backup.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");

                        doc_set.clear();
                        // doc_set_distinct.clear();
                    }
                }else if log_of_OBP_count == length_of_OBP {
                    transaction_original.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                    // transaction_original_distinct.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
                    // transaction_original_backup.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                    // transaction_original_distinct_backup.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
                    doc_set.clear();
                    // doc_set_distinct.clear();
                }else {
                    if (doc_set.len() >= transfer_limit) || (log_of_OBP_count == transaction_whole_len.clone()) {
                        transaction_scoring.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_scoring_distinct.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_original_backup.insert_many(doc_set.clone(),None).await.expect("failed to insert data to mongodb");
                        // transaction_original_distinct_backup.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
                        doc_set.clear();
                        // doc_set_distinct.clear();
                    }
                }
            }
            let disk_use_opt = AggregateOptions::builder().allow_disk_use(true).build();

            //insert original distinct
            transaction_original.aggregate(generate_distinct_logs("transacation_distinct"),disk_use_opt.clone()).await.expect("failed to deduplicate");
            //insert backup distinct
            // transaction_original_backup.aggregate(generate_distinct_logs("transacation_distinct_backup"),None).await.expect("failed to deduplicate");
            //insert scoring distinct
            transaction_scoring.aggregate(generate_distinct_logs("transacation_scoring_distinct"),disk_use_opt.clone()).await.expect("failed to deduplicate");
            println!("trans backup :{},trans original:{},trans scoring:{}",
                     transaction_original_distinct_backup.estimated_document_count(None).await?,
                     transaction_original_distinct.estimated_document_count(None).await?,
                     transaction_scoring_distinct.estimated_document_count(None).await?)


            // transaction_original.insert_many(doc_set,None).await.expect("failed to insert data to mongodb");
            // transaction_original_distinct.insert_many(doc_set_distinct.clone(),None).await.expect("failed to insert data to mongodb");
        }
        pb.finish_with_message("ending writing full data to mongo");
        // println!("start writing para space.. ");
        // println!("len of transaction:{},len of para space:{}",transactions.len().clone(),para_space.len().clone());
        // let para_space_original:Collection<Document> = client.database("esx_mining").collection("para_space_original");

        // println!("len of mongo trans:{},len of mongo para:{}, len of distinct mongo trans:{}",transaction_original.count_documents(None,None).await.unwrap(),para_space_original.count_documents(None,None).await.unwrap(),transaction_original_distinct.count_documents(None,None).await.unwrap());
        transactions_to_output = transactions[..length_of_OBP].to_vec();
    }



    // let transacation_obp =&transactions[..length_of_OBP];
    // let t_obp = transactions.clone_from_slice(transactions[..length_of_OBP.clone()].to_vec());
    Ok((transactions_to_output, unique_set))
}
async fn load_mongodb_to_vec() ->Result<(Vec<Vec<String>>,Vec<Document>,HashSet<String>)>{
    let client = Client::with_uri_str("mongodb://localhost").await.expect("failed to connect mongodb");
    let transaction_original_backup = client.database("esx_mining").collection::<EsxLog>("transacation_original_backup");
    let transaction_original_distinct = client.database("esx_mining").collection::<EsxLog>("transacation_distinct_backup");

    let mut transaction_collection = transaction_original_backup.find(None,None).await.expect("failed to connect to backup");
    // println!("back 里的数据量:{}",transaction_original_backup.count_documents(None,None).await.unwrap());
    let backup_len = transaction_original_backup.estimated_document_count(None).await.unwrap();
    let mut transcation_new:Vec<Vec<String>> = Vec::new();
    let mut uniqueSet:HashSet<String> = Default::default();
    let mut transaction_docs:Vec<Document> = Vec::new();
    let mut transaction_docs_distinct:Vec<Document> = Vec::new();
    // Loop through the results and print a summary and the comments:
    let pb = ProgressBar::new(backup_len);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}({per_sec},{eta})")
        .unwrap()
        .progress_chars("#>-"));
    while let Some(single_esx_log) = transaction_collection.try_next().await.expect("failed to change document to EsxLog") {
        pb.inc(1);
        // let single_esx_log: EsxLog = bson::from_document(single_log.clone()).expect("failed to change document to EsxLog");
        transcation_new.push(single_esx_log.to_logs_vec());
        let doc_tmp = bson::to_document(&single_esx_log).unwrap();
        transaction_docs.push(doc_tmp.clone());
        // println!("* {:?}", single_log.to_logs_vec());
    }
    pb.finish_and_clear();
    // println!("len of tran new:{}",transcation_new.len().clone());
    // let mut transaction_collection = transaction_original_distinct.find(None,None).await.unwrap();
    // while let Some(single_log) = transaction_collection.try_next().await? {
    //     // let doc: EsxLog = bson::from_document(single_log)?;

    //     let doc_tmp = bson::to_document(&single_log).unwrap();
    //     transaction_docs_distinct.push(doc_tmp.clone());

    //     // println!("* {:?}", single_log.to_logs_vec());
    // }
    // let para_space_original = client.database("esx_mining").collection::<EsxLog>("para_space_original");

    // let mut transaction_collection = para_space_original.find(None,None).await.unwrap();
    // let mut transcation_para:Vec<Vec<String>> = Vec::new();

    // // Loop through the results and print a summary and the comments:
    // while let Some(single_log) = transaction_collection.try_next().await? {
    //     // let doc: EsxLog = bson::from_document(single_log)?;
    //     transcation_para.push(single_log.to_logs_vec());

    //     // println!("* {:?}", single_log.to_logs_vec());
    // }
    //create unique HashSet



    Ok((transcation_new,transaction_docs,uniqueSet))
}