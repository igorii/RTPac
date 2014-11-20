#ifndef ENTROPY_H
#define ENTROPY_H

double element_frequency (
        unsigned long,
        unsigned long);

double entropy_of_distribution (
        unsigned long,
        unsigned long *,
        unsigned long);

double relative_entropy (
        unsigned long,
        unsigned long *,
        unsigned long,
        unsigned long *,
        unsigned long);

#endif
