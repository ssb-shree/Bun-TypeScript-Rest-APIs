export const daysFromNow = (numberOfDays: number): Date => {
  return new Date(Date.now() + numberOfDays * 24 * 60 * 60);
};

export const minsFromNow = (numberOfMins: number): Date => {
  return new Date(Date.now() + numberOfMins * 60);
};
