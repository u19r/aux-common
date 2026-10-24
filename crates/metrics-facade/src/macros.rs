#[macro_export]
macro_rules! counter {
    ($metric:expr $(,)?) => {
        $crate::counter($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::counter(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}
#[macro_export]
macro_rules! gauge {
    ($metric:expr $(,)?) => {
        $crate::gauge($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::gauge(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}

#[macro_export]
macro_rules! histogram {
    ($metric:expr $(,)?) => {
        $crate::histogram($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::histogram(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}
